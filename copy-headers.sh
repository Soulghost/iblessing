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

# copy embed libs
cd iblessing
mkdir vendor
cp -R ../../../submodules/capstone/include/capstone ./vendor/
cp -R ../../../submodules/keystone/include/keystone ./vendor/
cp -R ../../../submodules/unicorn/include/unicorn ./vendor/

cd ../../..
pwd