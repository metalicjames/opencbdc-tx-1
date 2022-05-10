#!/bin/bash

echo "Configuring..."

green="\033[0;32m"
cyan="\033[0;36m"
end="\033[0m"

set -e

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
  brew install llvm@13 googletest lcov make wget cmake
else
  apt update
  apt install -y build-essential wget cmake libgtest-dev libgmock-dev lcov git software-properties-common

  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
  add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-13 main"
  apt install -y clang-format-13 clang-tidy-13
  ln -s -f $(which clang-format-13) /usr/local/bin/clang-format
  ln -s -f $(which clang-tidy-13) /usr/local/bin/clang-tidy
fi

LEVELDB_VERSION="1.23"
echo -e "${green}Building LevelDB from sources...${end}"
wget https://github.com/google/leveldb/archive/${LEVELDB_VERSION}.tar.gz
tar xzvf ${LEVELDB_VERSION}.tar.gz
rm -rf ${LEVELDB_VERSION}.tar.gz
mv leveldb-${LEVELDB_VERSION} "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"
cd "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"
eval "cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DLEVELDB_BUILD_TESTS=0 -DLEVELDB_BUILD_BENCHMARKS=0 -DBUILD_SHARED_LIBS=0 ."
make -j$CPUS
sudo make install
cd ..
rm -rf "leveldb-${LEVELDB_VERSION}-${CMAKE_BUILD_TYPE}"

NURAFT_VERSION="1.3.0"
echo -e "${green}Building NuRaft from sources...${end}"
wget https://github.com/eBay/NuRaft/archive/v${NURAFT_VERSION}.tar.gz
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

sudo cp libnuraft.a /usr/local/lib
sudo cp -r ../include/libnuraft /usr/local/include

cd ../..
rm -rf "NuRaft-${NURAFT_VERSION}-${CMAKE_BUILD_TYPE}"

wget https://raw.githubusercontent.com/llvm/llvm-project/e837ce2a32369b2e9e8e5d60270c072c7dd63827/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py
sudo mv run-clang-tidy.py /usr/local/bin
