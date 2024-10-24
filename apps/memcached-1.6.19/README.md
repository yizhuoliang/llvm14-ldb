# Memcached 1.6.19 with LDB

## Building Memcached
1. Download and extract Memcached-1.6.19.tar.gz
  * ``wget https://memcached.org/files/memcached-1.6.19.tar.gz``
  * ``tar -xvzf memcached-1.6.19.tar.gz``

2. (Optional) For per-request tagging, apply patch
  * ``patch -ruN -d memcached-1.6.19 < LLVM_DIR/apps/memcached-1.6.19/memcached-1.6.19.patch``

3. Configure Memcached
  * ``cd memcached-1.6.19``
  * ``memcached-1.6.19> ./configure``

4. Replace Makefile with the one for LDB
  * ``memcached-1.6.19> cp LLVM_DIR/apps/memcached-1.6.19/Maekfile ./``

5. Make sure ROOT\_PATH in Makefile is set correctly to the LLVM root directory.

6. Build with Makefile
  * ``memcached-1.6.19> make``

7. Execute Memcached with LDB libary preloaded (Note that core 0 is used for Stack Scanner and core 1 is for Logger by default)
  * ``LD_PRELOAD=LLVM_DIR/libldb/libshim.so taskset 0xfffc ./memcached -p 16636 -v -m 10240 --threads=8`` 
