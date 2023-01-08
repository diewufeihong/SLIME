#  SLIME

### 1. Description

SLIME is a novel program-sensitive fuzzer that designs multiple property-aware queues and leverages a customized Upper Confidence Bound Variance-aware (UCB-V) algorithm. SLIME is developed based on top of [MOpt-AFL](https://github.com/puppet-meteor/MOpt-AFL). Read the [paper](./SLIME_TechReport.pdf) for more details.

### 2. Cite Information

Chenyang Lyu, Hong Liang, Shouling Ji, Xuhong Zhang, Binbin Zhao, Meng Han, Yun Li, Zhe Wang, Wenhai Wang, and Raheem Beyah, *SLIME: Program-sensitive Energy Allocation for Fuzzing*, ISSTA 2022 . 

### 3. Experiment Results

The experiment results can be found in https://drive.google.com/drive/folders/1dRgxgOJHSWZr1Y71rZZ9wBNmmkAp0Vq1?usp=sharing.  We only open source the crash files since the space is limited. 

### 4. Environment

- Tested on Ubuntu 16.04 64bit, LLVM 12.0.1 and CMake 3.14.0

### 5. Installation

Before install SLIME, user should prepare llvm.

- Download LLVM 12.0.1 source code from the [link](http://releases.llvm.org/download.html). 

- Compile with the following command.

  ```
  $ mkdir build
  $ cd build
  $ cmake \
      -DCLANG_INCLUDE_DOCS="OFF" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_BINUTILS_INCDIR=/usr/include/ \
      -DLLVM_BUILD_LLVM_DYLIB="ON" \
      -DLLVM_ENABLE_BINDINGS="OFF" \
      -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;libcxx;libcxxabi;libunwind;lld' \
      -DLLVM_ENABLE_WARNINGS="OFF" \
      -DLLVM_INCLUDE_BENCHMARKS="OFF" \
      -DLLVM_INCLUDE_DOCS="OFF" \
      -DLLVM_INCLUDE_EXAMPLES="OFF" \
      -DLLVM_INCLUDE_TESTS="OFF" \
      -DLLVM_LINK_LLVM_DYLIB="ON" \
      -DLLVM_TARGETS_TO_BUILD="host" \
      ../llvm/
  $ make -j4
  $ make install
  ```

#### Install SLIME

- Clone repository:

  ```
  $ git clone https://github.com/diewufeihong/SLIME
  ```

- Compile:

```
cd SLIME/SLIME && make && cd llvm_mode && make && cd ../llvm_mode_crash && make     
```

#### RUN SLIME

- Require to set the following environment variables

```
#   INPUT: input seed files
#   OUTPUT: output directory
#   Target_1: target program path compiled by llvm_mode_crash 
#   Target_2: target program path compiled by llvm_mode 
#   Target_2_bbfile: path where the bb_file of the target program is located
#   bb_file: files generated when compiling to record basic blocks' information 
#   CMDLINE: command line for a testing program and the target path is the same as Target_2
#   EDGE_SIZE_FILE_PATH: file path provided by the user. SLIME will create a file to keep track of how many edges the target has and decide the size of trace_bits at compile stage
```

- Compile the target program

```
#	Target_1:
 export AFL_LLVM_DOCUMENT_IDS=EDGE_SIZE_FILE_PATH
 CC=/path_to_SLIME/llvm_mode_crash/afl-clang-fast \
 CXX=/path_to_SLIME/llvm_mode_crash/afl-clang-fast++ \
 ./configure \
 --prefix=/path_to_compiled_program
 
#	Target_2:
 export AFL_LLVM_DOCUMENT_IDS=EDGE_SIZE_FILE_PATH
 CC=/path_to_SLIME/llvm_mode/afl-clang-fast \
 CXX=/path_to_SLIME/llvm_mode/afl-clang-fast++ \
 ./configure \
 --prefix=/path_to_compiled_program
```

- Start fuzz

```
export AFL_LLVM_DOCUMENT_IDS=EDGE_SIZE_FILE_PATH
/path_to_SLIME/afl-fuzz -i $INPUT -o $OUTPUT -H $Target_2_bbfile -A $Target_1 -L 0 -- $CMDLINE
```

### 6. Example: pdfimages

- Compile target:

```
tar -zxvf xpdf-4.00.tar.gz 
cp -r xpdf-4.00 xpdf-4.00_tmp_1 
cp -r xpdf-4.00 xpdf-4.00_tmp_2 

cd xpdf-4.00_tmp_1 
export CC="/SLIME/llvm_mode_crash/afl-clang-fast" 
export CXX="/SLIME/llvm_mode_crash/afl-clang-fast++" 
export AFL_LLVM_DOCUMENT_IDS="/xpdf-4.00_tmp_1/result.bb"
cmake . 
CC="/SLIME/llvm_mode_crash/afl-clang-fast" CXX="/SLIME_SKIP_new/llvm_mode_crash/afl-clang-fast++" make 

cd ../xpdf-4.00_tmp_2 
export CC="/SLIME/llvm_mode/afl-clang-fast"
export CXX="/SLIME/llvm_mode/afl-clang-fast++" 
export AFL_LLVM_DOCUMENT_IDS="/xpdf-4.00_tmp_1/result.bb"
cmake . 
CC="/SLIME/llvm_mode/afl-clang-fast" CXX="/SLIME/llvm_mode/afl-clang-fast++" make
```

- Start fuzz:

```
export AFL_LLVM_DOCUMENT_IDS="/xpdf-4.00_tmp_1/result.bb"

/SLIME/afl-fuzz -i /pdf_seed -o /fuzz_pdfimages -t 600+ -m 5000 -H /xpdf-4.00_tmp_2/xpdf/pdfimages.bb -A /xpdf-4.00_tmp_1/xpdf/pdfimages -L 0 -- /xpdf-4.00_tmp_2/xpdf/pdfimages @@ /dev/null 
```

### Citation:

```
@inproceedings{10.1145/3533767.3534385,
author = {Lyu, Chenyang and Liang, Hong and Ji, Shouling and Zhang, Xuhong and Zhao, Binbin and Han, Meng and Li, Yun and Wang, Zhe and Wang, Wenhai and Beyah, Raheem},
title = {SLIME: Program-Sensitive Energy Allocation for Fuzzing},
year = {2022},
isbn = {9781450393799},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3533767.3534385},
doi = {10.1145/3533767.3534385},
abstract = {The energy allocation strategy is one of the most popular techniques in fuzzing to improve code coverage and vulnerability discovery. The core intuition is that fuzzers should allocate more computational energy to the seed files that have high efficiency to trigger unique paths and crashes after mutation. Existing solutions usually define several properties, e.g., the execution speed, the file size, and the number of the triggered edges in the control flow graph, to serve as the key measurements in their allocation logics to estimate the potential of a seed. The efficiency of a property is usually assumed to be the same across different programs. However, we find that this assumption is not always valid. As a result, the state-of-the-art energy allocation solutions with static energy allocation logics are hard to achieve desirable performance on different programs. To address the above problem, we propose a novel program-sensitive solution, named SLIME, to enable adaptive energy allocation on the seed files with various properties for each program. Specifically, SLIME first designs multiple property-aware queues, with each queue containing the seed files with a specific property. Second, to improve the return of investment, SLIME leverages a customized Upper Confidence Bound Variance-aware (UCB-V) algorithm to statistically select a property queue with the most estimated reward, i.e., finding the most new unique execution paths and crashes. Finally, SLIME mutates the seed files in the selected property queue to perform property-adaptive fuzzing on a program. We evaluate SLIME against state-of-the-art open source fuzzers AFL, MOPT, AFL++, AFL++HIER, EcoFuzz, and TortoiseFuzz on 9 real-world programs. The results demonstrate that SLIME discovers 3.53X, 0.24X, 0.62X, 1.54X, 0.88X, and 3.81X more unique vulnerabilities compared to the above fuzzers, respectively. We will open source the prototype of SLIME to facilitate future fuzzing research.},
booktitle = {Proceedings of the 31st ACM SIGSOFT International Symposium on Software Testing and Analysis},
pages = {365–377},
numpages = {13},
keywords = {Vulnerability discovery, Fuzzing, Data-driven technique},
location = {Virtual, South Korea},
series = {ISSTA 2022}
}
```

