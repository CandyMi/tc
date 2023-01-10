# TinyCrypto

  `TinyCrypto`简称`TC`, 是适用于`C`与`C++`的**极简**加密、解密库.

# Features

  - [x] 支持的操作系统 (Win/BSD/Linux/MacOS等)

  - [x] 无需外部库依赖, 无平台与硬件依赖

  - [x] 小巧且丰富, 方便自行定制环境

  - [x] 外部易用性好, 可加快上手速度
  
  - [x] 可读性好、可维护性高、构建成本低

# Usage

  推荐使用者通过以下`2`种方式获取使用方法:

  1. 阅读`inc`文件夹下的相关源码头文件.

  2. 阅读`test`文件夹下的测试用例文件.

# Install

  1. 构建环境 `cd tc && cmake -B build -DENABLE_TEST=1`.

  2. 编译 `cmake --build build --config Release`.

  3. `cd build` 运行 `make install` 或 `ninja install` 或其他安装命令.

## 1. Folder

```bash
├── include
│   └── tc
│       ├── ...
│       └── tc.h
├── lib
│   ├── libcrypto.a
│   └── libcrypto.dylib
```

## 2. path

  使用`CMAKE`的时候如果不出意外的话, 最终的安装目录结构应该会如上所示. 然而您可以通过定义`CMAKE_INSTALL_PREFIX`宏来改变安装目录.(一般是: `C:\Program files(x86)`或`/usr/local`)

# Test Case

  如果您想构建出测试用例, 那么使用`CMAKE`定义`ENABLE_TEST`宏为`1`即可.

# Contribution

  如果您喜欢它并且想为它贡献部分代码, 请保证您遵循以下的代码贡献规范:

  If you like it and want to contribute some code to it, please follow these code contribution rules:
  
  * 请保证您以熟读`TC`相关源码实现. 并且愿意以`TC`相同规范的语法形式编写代码. (Please ensure that you are familiar with the `TC` related source code implementation. And willing to write code in the same canonical syntax as `TC`)

  * 由于您的代码将被冠以`TC`的前缀, 所以希望您的代码像其它算法实现一样可以兼容之前提到的平台. (Since your code will be prefixed with `TC`, expect your code to be as compatible with the aforementioned platforms as any other algorithmic implementation.)

  * 尽可能的复用`TC`已经实现的算法与接口, 编写的算法也尽可能让其它接口使用. (As far as possible to reuse the `TC` algorithm and interface has been implemented, the algorithm is written as far as possible to let other interfaces use.)

  * `TC`不依赖非标准库, 希望您贡献的代码也同样遵守. (`TC` does not rely on non-standard libraries, and we expect your code contributions to do the same)

  * 为了保证贡献到`TC`的代码质量, 请保证您的贡献至少拥有测试用例. (To ensure the quality of the code you contribute to the `TC`, make sure your contribution has at least test cases.)

# License

  [BSD 3-Clause "New" or "Revised" License](https://github.com/CandyMi/tc/blob/master/LICENSE).
