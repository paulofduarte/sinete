// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

// sinete_authenticate evaluates the device-owner authentication policy (Touch ID
// with a passcode fallback). evaluatePolicy is asynchronous, so we pump the run
// loop on the calling thread (which must be the main thread) until the reply
// arrives — this lets the system present the prompt.
int sinete_authenticate(const char *reason, char **err) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		LAPolicy policy = LAPolicyDeviceOwnerAuthentication;

		NSError *canErr = nil;
		if (![ctx canEvaluatePolicy:policy error:&canErr]) {
			if (err) {
				const char *m = canErr ? [[canErr localizedDescription] UTF8String]
				                       : "presence policy unavailable";
				*err = strdup(m);
			}
			return 0;
		}

		dispatch_semaphore_t sem = dispatch_semaphore_create(0);
		__block int ok = 0;
		__block char *errmsg = NULL;

		// stringWithUTF8String: returns nil for a NULL or invalid-UTF-8 reason, and
		// passing nil to localizedReason: would crash; fall back to a generic reason.
		NSString *nsReason = reason ? [NSString stringWithUTF8String:reason] : nil;
		if (!nsReason) {
			nsReason = @"authenticate to use a sinete key";
		}

		[ctx evaluatePolicy:policy
		    localizedReason:nsReason
		              reply:^(BOOL success, NSError *evalErr) {
			ok = success ? 1 : 0;
			if (!success && evalErr) {
				const char *d = [[evalErr localizedDescription] UTF8String];
				errmsg = strdup(d ? d : "user presence was not verified");
			}
			dispatch_semaphore_signal(sem);
		}];

		// Pump the run loop so the system can present the prompt, until the reply
		// signals. The semaphore both ends the loop and creates a happens-before
		// edge with the reply block, so reading ok/errmsg below is race-free — a
		// bare (even volatile) flag would not synchronise the block's writes.
		while (dispatch_semaphore_wait(sem, DISPATCH_TIME_NOW) != 0) {
			CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
		}
		dispatch_release(sem);

		if (!ok) {
			if (err) *err = errmsg ? errmsg : strdup("user presence was not verified");
			else if (errmsg) free(errmsg);
			return 0;
		}
		if (errmsg) free(errmsg);
		return 1;
	}
}
