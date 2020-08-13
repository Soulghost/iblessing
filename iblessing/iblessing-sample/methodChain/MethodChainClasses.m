//
//  MethodChainClasses.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "MethodChainClasses.h"

typedef void (^BlockWithMixedArgsV1)(NSString *a, BOOL b, id c, IBSRoot *d, BlockSubA *e, BlockSubB *f);
typedef NSString* (^BlockWithMixedArgsV2)(int a, BlockSubB *b, BOOL c, BOOL *d, int *e, Class f, BlockSubA *g);

@implementation IBSRoot

+ (void)rootClassMethodCallFromPrimary {
    
}

+ (void)rootClassMethodCallFromReflection {
    
}

+ (void)rootClassMethodCallFromInstanceClass {
    
}

+ (void)rootClassMethodCallFromBlockArgs {
    
}

- (void)rootInstanceMethodCallFromIvar {
    
}

- (void)rootInstanceMethodCallFromAllocate {
    
}

- (void)rootInstanceMethodCallFromBlockArgs {
    
}

@end


@implementation IBSCallTester

+ (void)testPrimaryCallToRootClassMethodAncestor {
    [IBSRoot rootClassMethodCallFromPrimary];
}

+ (void)testReflectionCallToRootClassMethodAncestor {
    [NSClassFromString(@"IBSRoot") rootClassMethodCallFromReflection];
}

+ (void)testInstanceCallToRootClassMethodAncestor {
    [[[[IBSRoot alloc] init] class] rootClassMethodCallFromInstanceClass];
}

- (void)testSelfCall {
    [self selfCallChain1];
}

- (void)selfCallChain1 {
    [self selfCallChain2];
}

- (void)selfCallChain2 {
    [self selfCallChain3];
}

- (void)selfCallChain3 {
    NSLog(@"self call end");
}

- (void)testLoop {
    [self testLoop];
}

- (void)testAllocateCall {
    IBSRoot *root = [[IBSRoot alloc] init];
    [root rootInstanceMethodCallFromAllocate];
}

- (void)testIvarCall {
    [self.root rootInstanceMethodCallFromIvar];
}

- (void)localStackBlockInovker:(void (^)(BlockSubA *sub))callback {
    callback([BlockSubA new]);
}

- (void)localStackBlockInvoker2:(BlockWithMixedArgsV1)callback {
    
}

- (void)localStackBlockInvoker3:(BlockWithMixedArgsV2)callback {
    
}

- (void)testSelfCapture {
    
}

- (void)testLocalBlockOnStack {
    BlockSubA *allocateCapture = [BlockSubA new];
    [self localStackBlockInovker:^(BlockSubA *sub) {
        [allocateCapture testAllocateCapture];
        [self testSelfCapture];
        [sub testCallFromBlockArg];
    }];
}

- (void)testSystemBlockOnStack {
    BlockSubA *allocateCapture = [BlockSubA new];
    [@[@1, @2, @3] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [allocateCapture testAllocateCapture];
        [self testSelfCapture];
    }];
}

- (void)testMixedBlockOnStack {
    [self localStackBlockInvoker2:^(NSString *a, BOOL b, id c, IBSRoot *d, BlockSubA *e, BlockSubB *f) {
        [[d class] rootClassMethodCallFromBlockArgs];
        [d rootInstanceMethodCallFromBlockArgs];
        [e testCallFromBlockArg];
        [f testCallFromblockArg];
        [self testSelfCapture];
    }];

    [self localStackBlockInvoker3:^NSString *(int a, BlockSubB *b, BOOL c, BOOL *d, int *e, __unsafe_unretained Class f, BlockSubA *g) {
        [b testCallFromblockArg];
        [g testCallFromBlockArg];
        [self testSelfCapture];
        return @"xxx";
    }];
}

@end

@implementation BlockSubA

- (void)testAllocateCapture {
    
}

- (void)testCallFromBlockArg {
    
}

@end

@implementation BlockSubB

- (void)testCallFromblockArg {
    
}

@end
