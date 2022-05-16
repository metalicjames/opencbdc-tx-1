#!/bin/bash

echo "Configuring..."

green="\033[0;32m"
cyan="\033[0;36m"
end="\033[0m"

set -e

SUDO=''
if (( $EUID != 0 )); then
    SUDO='sudo'
fi

CMAKE_BUILD_TYPE="Debug"
if [[ "$BUILD_RELEASE" == "1" ]]; then
  CMAKE_BUILD_TYPE="Release"
fi

CPUS=1
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  CPUS=$(grep -c ^processor /proc/cpuinfo)
elif [[ "$OSTYPE" == "darwin"* ]]; then
  CPUS=$(sysctl -n hw.ncpu)
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
  brew install llvm@13 googletest lcov make python3 wget cmake
  echo -e "${cyan}To run clang-tidy, you must add it to your path. Ex: ln -s /usr/local/opt/llvm@11/bin/clang-tidy /usr/local/bin/clang-tidy${end}"
else
  $SUDO apt update
  $SUDO apt install -y build-essential wget cmake libgtest-dev libgmock-dev lcov git software-properties-common unzip python3 python3-pip

  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | $SUDO apt-key add -
  $SUDO add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-13 main"
  $SUDO apt install -y clang-format-13 clang-tidy-13
  $SUDO ln -s -f $(which clang-format-13) /usr/local/bin/clang-format
  $SUDO ln -s -f $(which clang-tidy-13) /usr/local/bin/clang-tidy
fi

LEVELDB_VERSION="1.23"
echo -e "${green}Building LevelDB from sources...${end}"
wget https://github.com/google/leveldb/archive/${LEVELDB_VERSION}.tar.gz
rm -rf "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"
tar xzvf ${LEVELDB_VERSION}.tar.gz
rm -rf ${LEVELDB_VERSION}.tar.gz
mv leveldb-${LEVELDB_VERSION} "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"
cd "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"
eval "cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DLEVELDB_BUILD_TESTS=0 -DLEVELDB_BUILD_BENCHMARKS=0 -DBUILD_SHARED_LIBS=0 ."
make -j$CPUS
$SUDO make install
cd ..

NURAFT_VERSION="1.3.0"
echo -e "${green}Building NuRaft from sources...${end}"
wget https://github.com/eBay/NuRaft/archive/v${NURAFT_VERSION}.tar.gz
rm -rf "NuRaft-${NURAFT_VERSION}-${CMAKE_BUILD_TYPE}"
tar xzvf v${NURAFT_VERSION}.tar.gz
rm v${NURAFT_VERSION}.tar.gz
mv NuRaft-${NURAFT_VERSION} "NuRaft-${NURAFT_VERSION}-${CMAKE_BUILD_TYPE}"
cd "NuRaft-${NURAFT_VERSION}-${CMAKE_BUILD_TYPE}"
./prepare.sh
if [[ "$BUILD_RELEASE" == "1" ]]; then
  # If we're doing a release build, remove the examples and tests
  rm -rf examples tests
  mkdir examples
  mkdir tests
  touch examples/CMakeLists.txt
  touch tests/CMakeLists.txt
fi
mkdir -p build
cd build
eval "cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DDISABLE_SSL=1 .."
eval "make -j$CPUS static_lib"

$SUDO cp libnuraft.a /usr/local/lib
$SUDO cp -r ../include/libnuraft /usr/local/include

cd ../..

wget https://www.lua.org/ftp/lua-5.4.3.tar.gz
tar zxf lua-5.4.3.tar.gz
rm -rf lua-5.4.3.tar.gz
cd lua-5.4.3
make
$SUDO make install
cd ..

wget https://raw.githubusercontent.com/llvm/llvm-project/e837ce2a32369b2e9e8e5d60270c072c7dd63827/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py
$SUDO mv run-clang-tidy.py /usr/local/bin

wget https://github.com/ethereum/evmc/archive/eda05c6866ac06bd93d62b605cbec5839d85c221.zip
unzip eda05c6866ac06bd93d62b605cbec5839d85c221.zip
rm eda05c6866ac06bd93d62b605cbec5839d85c221.zip
cd evmc-eda05c6866ac06bd93d62b605cbec5839d85c221
mkdir build
cd build
cmake ..
make
$SUDO make install
cd ../..

wget https://github.com/ethereum/evmone/archive/be870917e8cefd2b125bd27375dd9d2409ff1f68.zip
unzip be870917e8cefd2b125bd27375dd9d2409ff1f68.zip
rm be870917e8cefd2b125bd27375dd9d2409ff1f68.zip
cd evmone-be870917e8cefd2b125bd27375dd9d2409ff1f68
rm -rf evmc
mv ../evmc-eda05c6866ac06bd93d62b605cbec5839d85c221 ./evmc
mkdir ./evmc/.git
cmake -S . -B build
cmake --build build --parallel
cd build
$SUDO make install
cd ../..
rm -rf evmone-be870917e8cefd2b125bd27375dd9d2409ff1f68

wget https://github.com/chfast/ethash/archive/e3e002ecc25ca699349aa62fa38e7b7cc5f653af.zip
unzip e3e002ecc25ca699349aa62fa38e7b7cc5f653af.zip
rm e3e002ecc25ca699349aa62fa38e7b7cc5f653af.zip
cd ethash-e3e002ecc25ca699349aa62fa38e7b7cc5f653af
mkdir build
cd build
cmake -DETHASH_BUILD_ETHASH=OFF -DETHASH_BUILD_TESTS=OFF ..
cmake --build . --parallel
$SUDO cp ./lib/keccak/libkeccak.a /usr/local/lib
$SUDO cp -r ../include/ethash /usr/local/include
cd ../..
