strace -e trace=\
	 %desc   \
         %file    \ 
         %fstat   \ 
         %fstatfs \ 
         %ipc     \ 
         %lstat   \ 
         %memory  \ 
         %network \ 
         %process \ 
         %pure    \ 
         %signal  \ 
         %stat    \ 
         %statfs  \ 
         %%stat   \ 
         %%statfs \ 
	gcc test.c -c
