//
//  MethodChainClasses.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "MethodChainClasses.h"

@implementation IBSRoot

+ (void)rootClassMethodCallFromPrimary {
    
}

+ (void)rootClassMethodCallFromReflection {
    
}

+ (void)rootClassMethodCallFromInstanceClass {
    
}

- (void)rootInstanceMethodCallFromIvar {
    
}

- (void)rootInstanceMethodCallFromAllocate {
    
}

+ (void)rootClassMethodCallFromSub {
    
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

- (void)testCallFromSub {
    void (^sub)(void) = ^ {
        [IBSRoot rootClassMethodCallFromSub];
    };
    sub();
    
    [@[@1, @2, @3] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [IBSRoot rootClassMethodCallFromSub];
    }];
    
    self.ivarBlock = [^{
        [IBSRoot rootClassMethodCallFromSub];
    } copy];
    self.ivarBlock();
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

@end

@implementation BlockSubA

- (void)testAllocateCapture {
    
}

- (void)testCallFromBlockArg {
    
}

@end
