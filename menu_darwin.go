package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>

static NSStatusBarButton *findStatusButton(NSView *v) {
	if ([v isKindOfClass:[NSStatusBarButton class]]) return (NSStatusBarButton *)v;
	for (NSView *sub in v.subviews) {
		NSStatusBarButton *b = findStatusButton(sub);
		if (b) return b;
	}
	return nil;
}

// ivar reads one of systray's private instance variables (its delegate is
// the status button's target and holds the status item and the menu).
static id ivar(id obj, const char *name) {
	Ivar v = class_getInstanceVariable([obj class], name);
	return v ? object_getIvar(obj, v) : nil;
}

// Opens the tray menu again. Clicking the status button from code doesn't
// show the menu outside a real mouse event, so pop the menu up directly. The
// menu has already been rebuilt (systray's updates wait for the main thread),
// and queuing behind systray's own close handling is all the waiting needed.
static void reopenTrayMenu(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		for (NSWindow *w in [NSApp windows]) {
			NSStatusBarButton *b = findStatusButton(w.contentView);
			if (!b) continue;
			// systray leaves the button's target nil, so its action goes to
			// the app delegate, which owns the status item and the menu.
			id owner = b.target ?: [NSApp delegate];
			NSStatusItem *item = ivar(owner, "statusItem");
			NSMenu *menu = ivar(owner, "menu");
			if (![item isKindOfClass:[NSStatusItem class]] || ![menu isKindOfClass:[NSMenu class]]) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			[item popUpStatusItemMenu:menu];
#pragma clang diagnostic pop
			return;
		}
	});
}
*/
import "C"

// macOS closes the menu on every click. To let several switches be flipped in
// a row, reopenMenu pops it up again under the icon.

func watchMenu() {}

// reopenMenu shows the tray menu again.
func reopenMenu() { C.reopenTrayMenu() }
