set -xe

cd cmake-build
true && rm -rf include
mkdir include
cd include
mkdir iblessing-core
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/v2 ./iblessing-core
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/core ./iblessing-core
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/infra ./iblessing-core
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/common ./iblessing-core
rsync -a --prune-empty-dirs --include '*.h' --include '*.hpp' --include '*/' --exclude '*' ../../iblessing/iblessing-core/scanner ./iblessing-core

cd ../..
pwd