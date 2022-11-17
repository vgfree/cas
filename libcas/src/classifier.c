/*
* Copyright(c) 2019-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include <syslog.h>
#include "cas_cache.h"
#include "classifier.h"
#include "classifier_defs.h"

#include <stddef.h>
#define list_for_each_prev_safe(pos, n, head)   \
        for (pos = (head)->prev, n = pos->prev; \
                        pos != (head);          \
                        pos = n, n = pos->prev)

/* Kernel log prefix */
#define CAS_CLS_LOG_PREFIX OCF_PREFIX_SHORT"[Classifier]"

/* Production version logs */
#define CAS_CLS_MSG(severity, format, ...) \
	syslog(severity, CAS_CLS_LOG_PREFIX " " format, ##__VA_ARGS__);

/* Set to 1 to enable debug logs */
#define CAS_CLASSIFIER_CLS_DEBUG 0

#if 1 == CAS_CLASSIFIER_CLS_DEBUG
/* Debug log */
#define CAS_CLS_DEBUG_MSG(format, ...) \
	CAS_CLS_MSG(LOG_INFO, format, ##__VA_ARGS__)
/* Trace log */
#define CAS_CLS_DEBUG_TRACE(format, ...) \
	trace_printk(format, ##__VA_ARGS__)

#else
#define CAS_CLS_DEBUG_MSG(format, ...)
#define CAS_CLS_DEBUG_TRACE(format, ...)
#endif

/* Done condition test - always accepts and stops evaluation */
static cas_cls_eval_t _cas_cls_done_test(struct cas_classifier *cls,
		struct cas_cls_condition *c, struct cas_cls_io *io,
		ocf_part_id_t part_id)
{
	cas_cls_eval_t ret = {.yes = 1, .stop = 1};
	return ret;
}

/* Generic condition constructor for conditions without operands (e.g. direct,
 * metadata) */
static int _cas_cls_generic_ctr(struct cas_classifier *cls,
		struct cas_cls_condition *c, char *data)
{
	if (data) {
		CAS_CLS_MSG(LOG_ERR, "Unexpected operand in condition\n");
		return -EINVAL;
	}
	return 0;
}

/* Generic condition destructor */
static void _cas_cls_generic_dtr(struct cas_classifier *cls,
		struct cas_cls_condition *c)
{
	if (c->context)
		env_free(c->context);
	c->context = NULL;
}

/* Numeric condition constructor. @data is expected to contain either
 * plain number string or range specifier (e.g. "gt:4096"). */
static int _cas_cls_numeric_ctr(struct cas_classifier* cls,
		struct cas_cls_condition *c, char *data)
{
	struct cas_cls_numeric *ctx;
	int result;
	char *ptr, *endptr;

	if (!data || strlen(data) == 0) {
		CAS_CLS_MSG(LOG_ERR, "Missing numeric condition operand\n");
		return -EINVAL;
	}

	ctx = env_malloc(sizeof(*ctx), 0);
	if (!ctx)
		return -ENOMEM;

	ctx->operator = cas_cls_numeric_eq;

	ptr = strpbrk(data, ":");
	if (ptr) {
		/* Terminate sub-string containing arithmetic operator */
		*ptr = '\0';
		++ptr;

		if (!strcmp(data, "eq")) {
			ctx->operator = cas_cls_numeric_eq;
		} else if (!strcmp(data, "ne")) {
			ctx->operator = cas_cls_numeric_ne;
		} else if (!strcmp(data, "lt")) {
			ctx->operator = cas_cls_numeric_lt;
		} else if (!strcmp(data, "gt")) {
			ctx->operator = cas_cls_numeric_gt;
		} else if (!strcmp(data, "le")) {
			ctx->operator = cas_cls_numeric_le;
		} else if (!strcmp(data, "ge")) {
			ctx->operator = cas_cls_numeric_ge;
		} else {
			CAS_CLS_MSG(LOG_ERR, "Invalid numeric operator \n");
			result = -EINVAL;
			goto error;
		}

	} else {
		/* Plain number case */
		ptr = data;
	}

	ctx->v_u64 = strtoll(ptr, &endptr, 10);
	if (ptr == endptr) {
		result = -EINVAL;
		CAS_CLS_MSG(LOG_ERR, "Invalid numeric operand\n");
		goto error;
	}

	CAS_CLS_DEBUG_MSG("\t\t - Using operator %d with value %llu\n",
			ctx->operator, ctx->v_u64);

	c->context = ctx;
	return 0;

error:
	env_free(ctx);
	return result;
}

/* Unsigned int numeric test function */
static cas_cls_eval_t _cas_cls_numeric_test_u(
		struct cas_cls_condition *c, uint64_t val)
{
	struct cas_cls_numeric *ctx = c->context;

	switch (ctx->operator) {
	case cas_cls_numeric_eq:
		return val == ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	case cas_cls_numeric_ne:
		return val != ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	case cas_cls_numeric_lt:
		return val < ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	case cas_cls_numeric_gt:
		return val > ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	case cas_cls_numeric_le:
		return val <= ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	case cas_cls_numeric_ge:
		return val >= ctx->v_u64 ? cas_cls_eval_yes : cas_cls_eval_no;
	}

	return cas_cls_eval_no;
}


/* Io class test function */
static cas_cls_eval_t _cas_cls_io_class_test(struct cas_classifier *cls,
		struct cas_cls_condition *c, struct cas_cls_io *io,
		ocf_part_id_t part_id)
{

	return _cas_cls_numeric_test_u(c, part_id);
}

/* LBA test function */
static cas_cls_eval_t _cas_cls_lba_test(
		struct cas_classifier *cls, struct cas_cls_condition *c,
		struct cas_cls_io *io, ocf_part_id_t part_id)
{
	uint64_t lba = io->aio->vb_length;

	return _cas_cls_numeric_test_u(c, lba);
}

/* Request size test function */
static cas_cls_eval_t _cas_cls_request_size_test(
		struct cas_classifier *cls, struct cas_cls_condition *c,
		struct cas_cls_io *io, ocf_part_id_t part_id)
{
	return _cas_cls_numeric_test_u(c, io->aio->vb_length);
}

/* Array of condition handlers */
static struct cas_cls_condition_handler _handlers[] = {
	{ "done", _cas_cls_done_test, _cas_cls_generic_ctr },
	{ "io_class", _cas_cls_io_class_test, _cas_cls_numeric_ctr, _cas_cls_generic_dtr },
	{ "lba", _cas_cls_lba_test, _cas_cls_numeric_ctr, _cas_cls_generic_dtr },
	{ "request_size", _cas_cls_request_size_test, _cas_cls_numeric_ctr, _cas_cls_generic_dtr },
	{ NULL }
};

/* Get condition handler for condition string token */
static struct cas_cls_condition_handler *_cas_cls_lookup_handler(
		const char *token)
{
	struct cas_cls_condition_handler *h = _handlers;

	while (h->token) {
		if (strcmp(h->token, token) == 0)
			return h;
		h++;
	}

	return NULL;
}

/* Deallocate condition */
static void _cas_cls_free_condition(struct cas_classifier *cls,
		struct cas_cls_condition *c)
{
	if (c->handler->dtr)
		c->handler->dtr(cls, c);
	env_free(c);
}

/* Allocate condition */
static struct cas_cls_condition * _cas_cls_create_condition(
		struct cas_classifier *cls, const char *token,
		char *data, int l_op)
{
	struct cas_cls_condition_handler *h;
	struct cas_cls_condition *c;
	int result;

	h = _cas_cls_lookup_handler(token);
	if (!h) {
		CAS_CLS_DEBUG_MSG("Cannot find handler for condition"
				" %s\n", token);
		return NULL;
	}

	c = env_malloc(sizeof(*c), 0);
	if (!c)
		return NULL;

	c->handler = h;
	c->context = NULL;
	c->l_op = l_op;

	if (c->handler->ctr) {
		result = c->handler->ctr(cls, c, data);
		if (result) {
			env_free(c);
			errno = -result;
			return NULL;
		}
	}

	CAS_CLS_DEBUG_MSG("\t\t - Created condition %s\n", token);

	return c;
}

/* Read single codnition from text input and return cas_cls_condition
 * representation. *rule pointer is advanced to point to next condition.
 * Input @rule string is modified to speed up parsing (selected bytes are
 * overwritten with 0).
 *
 * *l_op contains logical operator from previous condition and gets overwritten
 * with operator read from currently parsed condition.
 *
 * Returns pointer to condition if successfull.
 * Returns NULL if no more conditions in string.
 * Returns error pointer in case of syntax or runtime error.
 */
static struct cas_cls_condition *_cas_cls_parse_condition(
		struct cas_classifier *cls, char **rule,
		enum cas_cls_logical_op *l_op)
{
	char *token = *rule;	/* Condition token substring (e.g. file_size) */
	char *operand = NULL;	/* Operand substring (e.g. "lt:4096" or path) */
	char *ptr;		/* Current position in input string */
	char *last = token;	/* Last seen substring in condition */
	char op = 'X';		/* Logical operator at the end of condition */
	struct cas_cls_condition *c;	/* Output condition */

	if (**rule == '\0') {
		/* Empty condition */
		return NULL;
	}

	ptr = strpbrk(*rule, ":&|");
	if (!ptr) {
		/* No operands in condition (e.g. "metadata"), no logical
		 * operators following condition - we're done with parsing. */
		goto create;
	}

	if (*ptr == ':') {
		/* Operand found - terminate token string and move forward. */
		*ptr = '\0';
		ptr += 1;
		operand = ptr;
		last = ptr;

		ptr = strpbrk(ptr, "&|");
		if (!ptr) {
			/* No operator past condition - create rule and exit */
			goto create;
		}
	}

	/* Remember operator value and zero target byte to terminate previous
	 * string (token or operand) */
	op = *ptr;
	*ptr = '\0';

create:
	c = _cas_cls_create_condition(cls, token, operand, *l_op);
	*l_op = (op == '|' ? cas_cls_logical_or : cas_cls_logical_and);

	/* Set *rule to character past current condition and logical operator */
	if (ptr) {
		/* Set pointer for next iteration */
		*rule = ptr + 1;
	} else {
		/* Set pointer to terminating zero */
		*rule = last + strlen(last);
	}

	return c;
}

/* Parse all conditions in rule text description. @rule might be overwritten */
static int _cas_cls_parse_conditions(struct cas_classifier *cls,
		struct cas_cls_rule *r, char *rule)
{
	char *start;
	struct cas_cls_condition *c;
	enum cas_cls_logical_op l_op = cas_cls_logical_or;

	start = rule;
	for (;;) {
		c = _cas_cls_parse_condition(cls, &start, &l_op);
		if (!c)
			return -1;

		list_add_tail(&c->list, &r->conditions);
	}

	return 0;
}

static struct cas_classifier* cas_get_classifier(ocf_cache_t cache)
{
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);

	ENV_BUG_ON(!cache_priv);
	return cache_priv->classifier;
}

static void cas_set_classifier(ocf_cache_t cache,
		struct cas_classifier* cls)
{
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);

	ENV_BUG_ON(!cache_priv);
	cache_priv->classifier = cls;
}

void _cas_cls_rule_destroy(struct cas_classifier *cls,
		struct cas_cls_rule *r)
{
	struct list_head *item, *n;
	struct cas_cls_condition *c = NULL;

	if (!r)
		return;

	list_for_each_safe(item, n, &r->conditions) {
		c = list_entry(item, struct cas_cls_condition, list);
		list_del(item);
		_cas_cls_free_condition(cls, c);
	}

	env_free(r);
}

/* Destroy rule */
void cas_cls_rule_destroy(ocf_cache_t cache, struct cas_cls_rule *r)
{
	struct cas_classifier *cls = cas_get_classifier(cache);
	ENV_BUG_ON(!cls);
	_cas_cls_rule_destroy(cls, r);
}

/* Create rule from text description. @rule might be overwritten */
static struct cas_cls_rule *_cas_cls_rule_create(struct cas_classifier *cls,
		ocf_part_id_t part_id, char *rule)
{
	struct cas_cls_rule *r;
	int result;

	if (part_id == 0 || rule[0] == '\0')
		return NULL;

	r = env_malloc(sizeof(*r), 0);
	if (!r)
		return NULL;

	r->part_id = part_id;
	INIT_LIST_HEAD(&r->conditions);
	result = _cas_cls_parse_conditions(cls, r, rule);
	if (result) {
		_cas_cls_rule_destroy(cls, r);
		return NULL;
	}

	return r;
}

/* Update rule associated with given io class */
void cas_cls_rule_apply(ocf_cache_t cache,
		ocf_part_id_t part_id, struct cas_cls_rule *new)
{
	struct cas_classifier *cls;
	struct cas_cls_rule *old = NULL, *elem;
	struct list_head *item, *_n;

	cls = cas_get_classifier(cache);
	ENV_BUG_ON(!cls);

	env_rwlock_write_lock(&cls->lock);

	/* Walk through list of rules in reverse order (tail to head), visiting
	 * rules from high to low part_id */
	list_for_each_prev_safe(item, _n, &cls->rules) {
		elem = list_entry(item, struct cas_cls_rule, list);

		if (elem->part_id == part_id) {
			old = elem;
			list_del(item);
		}

		if (elem->part_id < part_id)
			break;
	}

	/* Insert new element past loop cursor */
	if (new)
		list_add(&new->list, item);

	env_rwlock_write_unlock(&cls->lock);

	_cas_cls_rule_destroy(cls, old);

	if (old)
		CAS_CLS_DEBUG_MSG("Removed rule for class %d\n", part_id);
	if (new)
		CAS_CLS_DEBUG_MSG("New rule for class  %d\n", part_id);

	return;
}

/*
 * Translate classification rule error from linux error code to CAS error code.
 * Internal classifier functions use PTR_ERR / ERR_PTR macros to propagate
 * error in pointers. These macros do not work well with CAS error codes, so
 * this function is used to form fine-grained CAS error code when returning
 * from classifier management function.
 */
static int _cas_cls_rule_err_to_cass_err(int err)
{
	switch (err) {
	case -ENOENT:
		return KCAS_ERR_CLS_RULE_UNKNOWN_CONDITION;
	case -EINVAL:
		return KCAS_ERR_CLS_RULE_INVALID_SYNTAX;
	default:
		return err;
	}
}

/* Create and apply classification rule for given class id */
static int _cas_cls_rule_init(ocf_cache_t cache, ocf_part_id_t part_id)
{
	struct cas_classifier *cls;
	struct ocf_io_class_info *info;
	struct cas_cls_rule *r;
	int result;

	cls = cas_get_classifier(cache);
	if (!cls)
		 return -EINVAL;

	info = env_zalloc(sizeof(*info), 0);
	if (!info)
		return -ENOMEM;

	result = ocf_cache_io_class_get_info(cache, part_id, info);
	if (result) {
		if (result == -OCF_ERR_IO_CLASS_NOT_EXIST)
			result = 0;
		goto exit;
	}

	if (strnlen(info->name, sizeof(info->name)) == sizeof(info->name)) {
		CAS_CLS_MSG(LOG_ERR, "IO class name not null terminated\n");
		result = -EINVAL;
		goto exit;
	}

	r = _cas_cls_rule_create(cls, part_id, info->name);
	if (!r) {
		result = _cas_cls_rule_err_to_cass_err(-errno);
		goto exit;
	}

	cas_cls_rule_apply(cache, part_id, r);

exit:
	env_free(info);
	return result;
}

/* Create classification rule from text description */
int cas_cls_rule_create(ocf_cache_t cache,
		ocf_part_id_t part_id, const char* rule,
		struct cas_cls_rule **cls_rule)
{
	struct cas_cls_rule *r = NULL;
	struct cas_classifier *cls;
	char *_rule;
	int ret;

	if (!cls_rule)
		return -EINVAL;

	cls = cas_get_classifier(cache);
	if (!cls)
		return -EINVAL;

	if (strnlen(rule, OCF_IO_CLASS_NAME_MAX) == OCF_IO_CLASS_NAME_MAX) {
		CAS_CLS_MSG(LOG_ERR, "IO class name not null terminated\n");
		return -EINVAL;
	}

	/* Make description copy as _cas_cls_rule_create might modify input
	 * string */
	_rule = env_strdup(rule, OCF_IO_CLASS_NAME_MAX);
	if (!_rule)
		 return -ENOMEM;

	r = _cas_cls_rule_create(cls, part_id, _rule);
	if (!r)
		ret = _cas_cls_rule_err_to_cass_err(-errno);
	else {
		CAS_CLS_DEBUG_MSG("Created rule: %s => %d\n", rule, part_id);
		*cls_rule = r;
		ret = 0;
	}

	env_free(_rule);
	return ret;
}

/* Deinitialize classifier and remove rules */
void cas_cls_deinit(ocf_cache_t cache)
{
	struct cas_classifier *cls;
	struct list_head *item, *n;
	struct cas_cls_rule *r = NULL;

	cls = cas_get_classifier(cache);
	ENV_BUG_ON(!cls);

	list_for_each_safe(item, n, &cls->rules) {
		r = list_entry(item, struct cas_cls_rule, list);
		list_del(item);
		_cas_cls_rule_destroy(cls, r);
	}

	env_free(cls);
	cas_set_classifier(cache, NULL);

	CAS_CLS_MSG(LOG_INFO, "Deinitialized IO classifier\n");

	return;
}

/* Initialize classifier context */
static struct cas_classifier *_cas_cls_init(void)
{
	struct cas_classifier *cls;

	cls = env_zalloc(sizeof(*cls), 0);
	if (!cls)
		return NULL;

	INIT_LIST_HEAD(&cls->rules);

	env_rwlock_init(&cls->lock);

	CAS_CLS_MSG(LOG_INFO, "Initialized IO classifier\n");

	return cls;
}

/* Initialize classifier and create rules for existing I/O classes */
int cas_cls_init(ocf_cache_t cache)
{
	struct cas_classifier *cls;
	unsigned result = 0;
	unsigned i;

	cls = _cas_cls_init();
	if (!cls)
		return -ENOMEM;
	cas_set_classifier(cache, cls);

	/* Update rules for all I/O classes except 0 - this is default for all
	 * unclassified I/O */
	for (i = 1; i < OCF_USER_IO_CLASS_MAX; i++) {
		result = _cas_cls_rule_init(cache, i);
		if (result)
			break;
	}

	if (result)
		cas_cls_deinit(cache);

	return result;
}

/* Determine whether io matches rule */
static cas_cls_eval_t cas_cls_process_rule(struct cas_classifier *cls,
		struct cas_cls_rule *r, struct cas_cls_io *io,
		ocf_part_id_t *part_id)
{
	struct list_head *item;
	struct cas_cls_condition *c;
	cas_cls_eval_t ret = cas_cls_eval_no, rr;

	CAS_CLS_DEBUG_TRACE(" Processing rule for class %d\n", r->part_id);
	list_for_each(item, &r->conditions) {

		c = list_entry(item, struct cas_cls_condition, list);

		if (!ret.yes && c->l_op == cas_cls_logical_and)
			break;

		rr = c->handler->test(cls, c, io, *part_id);
		CAS_CLS_DEBUG_TRACE("  Processing condition %s => %d, stop:%d "
				"(l_op: %d)\n", c->handler->token, rr.yes,
				rr.stop, (int)c->l_op);

		ret.yes = (c->l_op == cas_cls_logical_and) ?
			rr.yes && ret.yes :
			rr.yes || ret.yes;
		ret.stop = rr.stop;

		if (ret.stop)
			break;
	}

	CAS_CLS_DEBUG_TRACE("  Rule %d output => %d stop: %d\n", r->part_id,
		ret.yes, ret.stop);

	return ret;
}

/* Fill in cas_cls_io for given aio - it is assumed that ctx is
 * zeroed upon entry */
static void _cas_cls_get_aio_context(struct cas_aio *aio,
	struct cas_cls_io *ctx)
{
	if (!aio)
		return;
	ctx->aio = aio;

	return;
}

/* Determine I/O class for aio */
ocf_part_id_t cas_cls_classify(ocf_cache_t cache, struct cas_aio *aio)
{
	struct cas_classifier *cls;
	struct cas_cls_io io = {};
	struct list_head *item;
	struct cas_cls_rule *r;
	ocf_part_id_t part_id = 0;
	cas_cls_eval_t ret;

	cls = cas_get_classifier(cache);
	if (!cls)
		return 0;

	_cas_cls_get_aio_context(aio, &io);

	env_rwlock_read_lock(&cls->lock);
	CAS_CLS_DEBUG_TRACE("%s\n", "Starting processing");
	list_for_each(item, &cls->rules) {
		r = list_entry(item, struct cas_cls_rule, list);
		ret = cas_cls_process_rule(cls, r, &io, &part_id);
		if (ret.yes)
			part_id = r->part_id;
		if (ret.stop)
			break;
	}
	env_rwlock_read_unlock(&cls->lock);

	return part_id;
}

