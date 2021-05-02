1. x0 x1 使用特定的 mask 来区分内容，比如 self sel - 不够通用化 (SelfInstanceTrickMask， SelfSelectorMark)
2. 如果是 block 需要构造 x0 指向 block 对象，然后在堆上构建一个合法 block 对象，最后还要初始化入参
3. state 路径分裂只 restore 了 cpu 和栈，内存未回滚，因此存在一定的误差
