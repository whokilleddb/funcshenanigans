# funcshenanigans

This research was inspired by the [Shellcode Fluctuation](https://github.com/mgeeky/ShellcodeFluctuation) technique along with [this blog about a self mutating program](https://ephemeral.cx/2013/12/writing-a-self-mutating-x86_64-c-program/). So far we have seen the fluctuation technique be used for things like Shellcode and entire PEs, but I wanted to try and use this technique for something simpler - fluctuating just one function. 

The goal was to experiment with function bounds, memory protection and VEHs. This repositgory documents the results of such experiments in a very rough way, documenting the techniques as we go. 

## Pre-requisites 

- Mingw Compiler 
- Make 

## Bounding functions 

First, let's create a function which we would target. I am defining a demo function as: 

```c
__attribute__((aligned(FUNC_SIZE)))
VOID fluctuate() {
	for (int i = 0; i < 5; i++) {
		SYSTEMTIME st = { 0 };
		GetLocalTime(&st);

		printf("\tCurrent Time: %02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
		Sleep(1000);
	}
  printf("\n");
}
```

The function just prints the current time in 1s intervals for 5 secs. The thing to note here is the `__attribute__((aligned(FUNC_SIZE)))` part. So ideally we would like to know an upper limit for how much memory we are dealing with. The `FUNC_SIZE` is set to 4096, so we know 