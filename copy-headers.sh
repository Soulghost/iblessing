set -xe

cd cmake-build
true && rm -rf include
mkdir include
cd include
mkdir iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/v2 ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/core ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/infra ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/common ./iblessing
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/scanner ./iblessing

cd ../..
pwd