if [ $# != 2 ]; then
        echo -e "USAGE:\n\tpkg.sh \$project \$branch"
        exit 1
fi

CAS_VERSION=1.0.1


ORG=`pwd`
TGT=$1
DIR=$ORG/rpmbuild/$TGT
SRC=/tmp/$TGT-${CAS_VERSION}
TAR=/tmp/${TGT}-${CAS_VERSION}.tar.gz

#1# 清理环境
rm -rf $DIR
rm -rf $SRC
rm -rf $TAR


#2# 获取代码
git clone https://git.iodepth.com/depth/${TGT}.git $SRC -b $2


#3# 获取版本
cd $SRC
PACKAGE_RELEASE=`git rev-list --count HEAD`
PACKAGE_REVERSION=`git rev-parse --short HEAD`
echo ${CAS_VERSION} > /tmp/$TGT-${CAS_VERSION}/VERSION

git submodule init
git submodule update
git submodule foreach git submodule init
git submodule foreach git submodule update

cd $ORG


#4# 代码打包
#tar -czvf $TAR -C /tmp/$TGT-${CAS_VERSION} --exclude=./.* .
tar -czvf $TAR -C /tmp/$TGT-${CAS_VERSION} .

#5# 准备资源
mkdir -p $DIR/{RPMS,SRPMS,BUILD,SOURCES,SPECS}
mv $TAR $DIR/SOURCES/
cp ${TGT}.spec $DIR/SPECS/

#5# 开始打包
home="_topdir $DIR"

eval QA_RPATHS=$[ 0x0002|0x0010 ] rpmbuild --nodebuginfo --define \"$home\" --define \"_version ${CAS_VERSION}\" --define \"_release ${PACKAGE_RELEASE}\" --define \"_reversion ${PACKAGE_REVERSION}\" -vv -ba $DIR/SPECS/${TGT}.spec
