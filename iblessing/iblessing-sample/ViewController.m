//
//  ViewController.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "ViewController.h"
#import "iblessing_sample-Swift.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *ret =  [[SwiftObjcEntry new] main];
    NSLog(@"ret %@", ret);
}


@end
