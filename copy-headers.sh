set -xe

cd cmake-build
true && rm -rf include
mkdir include
cd include
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing/v2/iblessing .
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing/core ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing/infra ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing/common ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing/scanner ./iblessing

cd ../..
pwd