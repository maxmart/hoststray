package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static NSStatusBarButton *findStatusButton(NSView *v) {
	if ([v isKindOfClass:[NSStatusBarButton class]]) return (NSStatusBarButton *)v;
	for (NSView *sub in v.subviews) {
		NSStatusBarButton *b = findStatusButton(sub);
		if (b) return b;
	}
	return nil;
}

// Clicks our status item again, as the user would. The delay lets the menu
// that just closed finish detaching (systray does that on the next run-loop
// turn), so the click opens the menu instead of being swallowed.
static void reopenTrayMenu(void) {
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 150 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
		for (NSWindow *w in [NSApp windows]) {
			NSStatusBarButton *b = findStatusButton(w.contentView);
			if (b && b.target && b.action) {
				[NSApp sendAction:b.action to:b.target from:b];
				return;
			}
		}
	});
}
*/
import "C"

// macOS closes the menu on every click. To let several switches be flipped in
// a row, reopenMenu clicks the status item again; AppKit opens the menu under
// the icon, where it was.

func watchMenu() {}

// reopenMenu shows the tray menu again.
func reopenMenu() { C.reopenTrayMenu() }
