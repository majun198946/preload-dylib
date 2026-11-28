// AISPreloadCert.m —— v2：全能签启动自动导入预置证书
//
// 【v2 相对 v1 的致命修正】
// v1 用 class_getInstanceMethod 扫全类找 importCertificateBundleFromZipURL:...
// 反汇编确认（NSKSign 27.1.2，arm64）：
//   +[AISCertificateZipBundleImporter importCertificateBundleFromZipURL:password:presenter:error:]
//   types = B48@0:8@16@24@32^@40   →  BOOL (id, SEL, id zipURL, id password, id presenter, NSError **)
// 它是 **类方法（+）**，该类的 baseMethods 为 0x0（完全没有实例方法）。
// 所以 v1 的 class_getInstanceMethod 恒返回 nil → 永远打印"没找到"直接放弃。
//
// 【v2 做法】
// 1. 硬编码类名 AISCertificateZipBundleImporter，直接取 class_getClassMethod（快、准）
// 2. 类名取不到时（版本升级改名）才扫全类，且**类方法/实例方法都查**
// 3. 用 IMP 直接强转调用（不用 NSInvocation —— v1 里的 [inv retainArguments]
//    会对 ^@（NSError **）参数做 objc_retain，指向栈变量，属未定义行为）
// 4. 输出类型编码自检：返回类型不是 B/c/i 就拒调，避免把 BOOL 当 id 读
// 5. 主路径失败 → 降级走 AISCertImportFromFile 的分解路径
//      + finalizeP12AtCopiedURL:password:error:            types @40@0:8@16@24^@32
//      + finalizeProvisionAtCopiedURL:presenter:silent:error: types @44@0:8@16@24B32^@36
//    silent=YES 完全无 UI
//
// 依赖资源（repack 脚本放在 .app 根目录）：
//   preload_cert.zip  —— 内含 cert.p12 + cert.mobileprovision
//   preload_cert.txt  —— p12 密码（无换行最稳）
//
// 编译：GitHub Actions（.github/workflows/build.yml）或本地 Xcode
// 注意：不使用 objc_msgSend 强转（Xcode 15+ 标 unavailable），全部走 IMP。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString *const kZipBaseName    = @"preload_cert";
static NSString *const kDoneKey        = @"ais_preload_cert_done_v2";
static NSString *const kTryCountKey    = @"ais_preload_cert_tries_v2";
static NSString *const kHardClass      = @"AISCertificateZipBundleImporter";
static NSString *const kFileClass      = @"AISCertImportFromFile";
static NSString *const kZipSelName     = @"importCertificateBundleFromZipURL:password:presenter:error:";

#pragma mark - 函数指针类型（严格照二进制里的 types 编码）

typedef BOOL (*AISZipImportFn)(id self_, SEL _cmd, id zipURL, id password,
                              id presenter, NSError **err);          // B48@0:8@16@24@32^@40
typedef id   (*AISFinalizeP12Fn)(id self_, SEL _cmd, id copiedURL,
                                 id password, NSError **err);        // @40@0:8@16@24^@32
typedef id   (*AISFinalizeMpFn)(id self_, SEL _cmd, id copiedURL,
                                id presenter, BOOL silent,
                                NSError **err);                      // @44@0:8@16@24B32^@36

#pragma mark - 日志

#define AISLog(fmt, ...) NSLog(@"[preload] " fmt, ##__VA_ARGS__)

#pragma mark - 顶层 VC

static UIViewController *AISTopViewController(void) {
    UIWindow *keyWin = nil;
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w.isKeyWindow) { keyWin = w; break; }
        }
        if (keyWin) break;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop

    UIViewController *vc = keyWin.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if ([vc isKindOfClass:[UINavigationController class]])
        vc = ((UINavigationController *)vc).visibleViewController ?: vc;
    if ([vc isKindOfClass:[UITabBarController class]])
        vc = ((UITabBarController *)vc).selectedViewController ?: vc;
    return vc;
}

#pragma mark - 方法查找（类方法优先，失败再扫全类）

// 返回 Method，并通过 isClass 告诉调用方是类方法还是实例方法
static Method AISFindMethod(Class c, SEL sel, BOOL *isClass) {
    if (isClass) *isClass = NO;
    if (!c) return NULL;

    Method m = class_getClassMethod(c, sel);
    if (m) { if (isClass) *isClass = YES; return m; }

    m = class_getInstanceMethod(c, sel);
    if (m) { if (isClass) *isClass = NO; return m; }
    return NULL;
}

static Class AISScanForClass(SEL sel) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return Nil;
    Class *list = (Class *)malloc(sizeof(Class) * (size_t)count);
    if (!list) return Nil;
    count = objc_getClassList(list, count);

    Class found = Nil;
    for (int i = 0; i < count; i++) {
        Class c = list[i];
        if (class_getClassMethod(c, sel) || class_getInstanceMethod(c, sel)) {
            found = c;
            break;
        }
    }
    free(list);
    return found;
}

// 返回类型是否为 BOOL 类（'B'=C++bool, 'c'=char, 'i'=int）
static BOOL AISReturnIsBool(Method m) {
    const char *types = method_getTypeEncoding(m);
    if (!types || !types[0]) return NO;
    return (types[0] == 'B' || types[0] == 'c' || types[0] == 'i');
}

#pragma mark - 资源准备

static void AISPurgeStagingCache(void) {
    // 它内部会用 AppSupport 下的 staging 目录；顺手清一下旧残留，避免用到上次的半成品
    SEL sel = NSSelectorFromString(@"purgePasswordPromptStagingZipArtifacts");
    Class cls = objc_getClass(kHardClass.UTF8String);
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP imp = method_getImplementation(m);
    void (*fn)(id, SEL) = (void (*)(id, SEL))imp;
    @try { fn((id)cls, sel); } @catch (NSException *e) { AISLog(@"purge 异常: %@", e); }
}

static NSString *AISBundlePath(NSString *name, NSString *ext) {
    NSString *p = [[NSBundle mainBundle] pathForResource:name ofType:ext];
    if (p) return p;
    p = [[[NSBundle mainBundle] bundlePath]
         stringByAppendingPathComponent:
         (ext.length ? [name stringByAppendingPathExtension:ext] : name)];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return p;
    // Documents 兜底（A 层脚本也往这里放过一份）
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *d = docs.firstObject;
    NSString *q = [d stringByAppendingPathComponent:
                   (ext.length ? [name stringByAppendingPathExtension:ext] : name)];
    if (d && [[NSFileManager defaultManager] fileExistsAtPath:q]) return q;
    return nil;
}

static NSString *AISReadPassword(NSString *zipPath) {
    NSString *txt = AISBundlePath(kZipBaseName, @"txt");
    if (txt) {
        NSString *raw = [NSString stringWithContentsOfFile:txt
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
        if (raw) {
            NSString *s = [raw stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            // 去掉可能的 BOM
            if ([s hasPrefix:@"\uFEFF"]) s = [s substringFromIndex:1];
            AISLog(@"密码来源: txt（长度 %lu）", (unsigned long)s.length);
            return s;
        }
    }
    // 没有 txt 就退到同目录 p12/txt 约定，最后默认 "1"（与 ksqsign -p 1 一致）
    AISLog(@"没有 %@.txt，按约定用密码 \"1\"", kZipBaseName);
    return @"1";
}

#pragma mark - 主路径：整包 zip 导入

static BOOL AISRunZipImport(NSString *zipPath, NSString *pwd,
                            UIViewController *presenter, NSError **outErr) {
    SEL sel = NSSelectorFromString(kZipSelName);

    Class cls = objc_getClass(kHardClass.UTF8String);
    if (!cls) {
        AISLog(@"硬编码类 %@ 不存在，扫全类", kHardClass);
        cls = AISScanForClass(sel);
    }
    if (!cls) {
        AISLog(@"没找到实现了 %@ 的类", kZipSelName);
        return NO;
    }

    BOOL isClass = NO;
    Method m = AISFindMethod(cls, sel, &isClass);
    if (!m) {
        AISLog(@"%@ 找到了但方法不存在", cls);
        return NO;
    }
    if (!AISReturnIsBool(m)) {
        AISLog(@"返回类型不是 BOOL（types=%s），拒调", method_getTypeEncoding(m));
        return NO;
    }
    AISLog(@"调用 %@ (%@方法)", cls, isClass ? @"类" : @"实例");

    id target = (id)cls;
    if (!isClass) {
        // 罕见：万一以后改成实例方法，用 alloc/init 造一个
        SEL allocSel = NSSelectorFromString(@"alloc");
        Method allocM = class_getClassMethod(cls, allocSel);
        id obj = nil;
        if (allocM) obj = ((id (*)(id, SEL))method_getImplementation(allocM))((id)cls, allocSel);
        if (obj) {
            SEL initSel = NSSelectorFromString(@"init");
            Method initM = class_getInstanceMethod(object_getClass(obj), initSel);
            if (initM) obj = ((id (*)(id, SEL))method_getImplementation(initM))(obj, initSel);
            target = obj;
        }
    }

    AISZipImportFn fn = (AISZipImportFn)method_getImplementation(m);
    NSError *err = nil;
    BOOL ok = NO;
    @try {
        ok = fn(target, sel, [NSURL fileURLWithPath:zipPath], pwd, presenter, &err);
    } @catch (NSException *e) {
        AISLog(@"zip 导入抛异常: %@ %@", e.name, e.reason);
        return NO;
    }

    if (outErr) *outErr = err;
    AISLog(@"zip 导入返回 ok=%d err=%@", ok, err.localizedDescription ?: @"(nil)");
    return ok;
}

#pragma mark - 降级路径：p12 / mobileprovision 分开导入（silent）

static NSString *AISAppSupportCopy(NSString *src, NSString *prefix) {
    if (!src) return nil;
    NSString *support = [NSSearchPathForDirectoriesInDomains(
                          NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    if (!support) return nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:support
                              withIntermediateDirectories:YES attributes:nil error:NULL];
    NSString *name = [prefix stringByAppendingPathExtension:src.pathExtension];
    NSString *dst = [support stringByAppendingPathComponent:name];
    [[NSFileManager defaultManager] removeItemAtPath:dst error:NULL];
    NSError *e = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:src toPath:dst error:&e]) {
        AISLog(@"拷贝到 AppSupport 失败: %@", e.localizedDescription);
        return nil;
    }
    return dst;
}

static BOOL AISRunSplitImport(UIViewController *presenter, NSError **outErr) {
    // 需要包里直接有 preload_cert.p12 与 preload_cert.mobileprovision（zip 导入失败时用）
    NSString *p12Src = AISBundlePath(kZipBaseName, @"p12");
    NSString *mpSrc  = AISBundlePath(kZipBaseName, @"mobileprovision");
    if (!p12Src || !mpSrc) {
        AISLog(@"降级路径缺少 %@.p12 或 %@.mobileprovision，跳过", kZipBaseName, kZipBaseName);
        return NO;
    }

    Class cls = objc_getClass(kFileClass.UTF8String);
    if (!cls) { AISLog(@"类 %@ 不存在，降级失败", kFileClass); return NO; }

    NSString *pwd = AISReadPassword(nil);
    NSString *p12Copy = AISAppSupportCopy(p12Src, @"preload_p12");
    NSString *mpCopy  = AISAppSupportCopy(mpSrc,  @"preload_mp");

    // ① p12
    SEL s1 = NSSelectorFromString(@"finalizeP12AtCopiedURL:password:error:");
    Method m1 = class_getClassMethod(cls, s1);
    if (!m1) m1 = class_getInstanceMethod(cls, s1);
    if (!m1) { AISLog(@"没有 finalizeP12AtCopiedURL，降级失败"); return NO; }
    if (method_getTypeEncoding(m1)[0] != '@') {
        AISLog(@"p12 finalize 返回类型异常: %s", method_getTypeEncoding(m1));
    }
    id p12Ret = nil;
    NSError *e1 = nil;
    @try {
        AISFinalizeP12Fn fn = (AISFinalizeP12Fn)method_getImplementation(m1);
        p12Ret = fn((id)cls, s1, [NSURL fileURLWithPath:p12Copy], pwd, &e1);
    } @catch (NSException *e) {
        AISLog(@"finalizeP12 异常: %@", e);
        return NO;
    }
    AISLog(@"finalizeP12 返回 %@ err=%@", p12Ret, e1.localizedDescription ?: @"(nil)");
    if (!p12Ret) { if (outErr) *outErr = e1; return NO; }

    // ② mobileprovision（silent=YES，不弹框）
    SEL s2 = NSSelectorFromString(@"finalizeProvisionAtCopiedURL:presenter:silent:error:");
    Method m2 = class_getClassMethod(cls, s2);
    if (!m2) m2 = class_getInstanceMethod(cls, s2);
    if (!m2) {
        // 再退一档：没有 silent 版本，用带 presenter 的那版
        s2 = NSSelectorFromString(@"finalizeProvisionAtCopiedURL:presenter:error:");
        m2 = class_getClassMethod(cls, s2);
        if (!m2) m2 = class_getInstanceMethod(cls, s2);
        AISLog(@"用非 silent 版 finalizeProvision");
    }
    if (!m2) { AISLog(@"没有 finalizeProvision，降级失败"); return NO; }

    id mpRet = nil;
    NSError *e2 = nil;
    @try {
        AISFinalizeP12Fn fn = (AISFinalizeP12Fn)method_getImplementation(m2);
        mpRet = fn((id)cls, s2, [NSURL fileURLWithPath:mpCopy], presenter, &e2);
    } @catch (NSException *e) {
        // 参数个数不匹配的兜底：试 silent 版本
        AISLog(@"finalizeProvision 异常 %@，试 silent 版", e);
        SEL s3 = NSSelectorFromString(@"finalizeProvisionAtCopiedURL:presenter:silent:error:");
        Method m3 = class_getClassMethod(cls, s3);
        if (m3) {
            AISFinalizeMpFn f3 = (AISFinalizeMpFn)method_getImplementation(m3);
            NSError *e3 = nil;
            mpRet = f3((id)cls, s3, [NSURL fileURLWithPath:mpCopy], presenter, YES, &e3);
            e2 = e3;
        }
    }
    AISLog(@"finalizeProvision 返回 %@ err=%@", mpRet, e2.localizedDescription ?: @"(nil)");
    if (outErr) *outErr = e2;
    return (mpRet != nil);
}

#pragma mark - 主流程

static BOOL AISIsDone(void) {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kDoneKey];
}

static void AISMarkDone(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setBool:YES forKey:kDoneKey];
    [d synchronize];
}

static void AISPreloadRun(void) {
    @autoreleasepool {
        if (AISIsDone()) {
            AISLog(@"已导入过（%@），跳过", kDoneKey);
            return;
        }

        NSString *zipPath = AISBundlePath(kZipBaseName, @"zip");
        if (!zipPath) {
            AISLog(@"包里没有 %@.zip，退出", kZipBaseName);
            return;
        }

        NSUserDefaults *def = [NSUserDefaults standardUserDefaults];
        NSInteger tries = [def integerForKey:kTryCountKey] + 1;
        [def setInteger:tries forKey:kTryCountKey];
        AISLog(@"第 %ld 次尝试，zip=%@", (long)tries, zipPath.lastPathComponent);

        UIViewController *presenter = AISTopViewController();
        if (!presenter) {
            AISLog(@"没有 presenter，下次重试");
            return;
        }

        AISPurgeStagingCache();

        NSString *pwd = AISReadPassword(zipPath);
        NSError *err = nil;
        BOOL ok = AISRunZipImport(zipPath, pwd, presenter, &err);

        if (!ok) {
            AISLog(@"zip 路径失败，降级分解导入");
            NSError *err2 = nil;
            ok = AISRunSplitImport(presenter, &err2);
            if (!ok) {
                AISLog(@"降级也失败: %@", err2.localizedDescription ?: @"(nil)");
            }
        }

        if (ok) {
            AISMarkDone();
            [def setInteger:0 forKey:kTryCountKey];
            AISLog(@"证书已导入，后续启动不再执行");
        } else if (tries >= 8) {
            // 防无限重试：连续 8 次同 App 生命周期内失败就不再骚扰
            AISMarkDone();
            AISLog(@"连续 %ld 次失败，停止重试（需换包或排查资源）", (long)tries);
        }
    }
}

// 启动后延迟执行；第一次失败后再补两次
__attribute__((constructor))
static void AISPreloadEntry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSArray *delays = @[@1.0, @2.5, @5.0];
        for (NSNumber *d in delays) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(d.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if (!AISIsDone()) AISPreloadRun();
            });
        }
    });
}
