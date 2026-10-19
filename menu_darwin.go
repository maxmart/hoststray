package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework QuartzCore
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <QuartzCore/QuartzCore.h>

// systray's app delegate owns the status item and the menu, in private
// instance variables.
static id systrayIvar(const char *name) {
	id owner = [NSApp delegate];
	Ivar v = owner ? class_getInstanceVariable([owner class], name) : NULL;
	return v ? object_getIvar(owner, v) : nil;
}

static void onMain(dispatch_block_t b) {
	if (pthread_main_np()) b(); else dispatch_sync(dispatch_get_main_queue(), b);
}

// A switch was flipped inside the open menu, so there is nothing to reopen.
static BOOL switchUsed = NO;

// A menu row with a label and a switch. Clicking anywhere on it flips the
// switch; controls inside a menu item's view don't close the menu.
// A toggle drawn by hand: NSSwitch draws itself grey in a menu (menus never
// become the active window), and it can't be given an "on" colour. Layers
// animate on their own, so the knob slides smoothly even while the menu is
// tracking the mouse.
@interface HTToggle : NSView
@property (nonatomic) BOOL on;
@property (nonatomic) BOOL enabled;
@end

@implementation HTToggle {
	CALayer *_track, *_knob;
}

- (instancetype)initWithFrame:(NSRect)frame {
	if ((self = [super initWithFrame:frame])) {
		self.wantsLayer = YES;
		_track = [CALayer layer];
		_knob = [CALayer layer];
		_knob.shadowOpacity = 0.3;
		_knob.shadowRadius = 1;
		_knob.shadowOffset = CGSizeMake(0, -0.5);
		[self.layer addSublayer:_track];
		[self.layer addSublayer:_knob];
		_enabled = YES;
		[self layout:NO];
	}
	return self;
}

- (void)setOn:(BOOL)on {
	if (on == _on) return;
	_on = on;
	[self layout:self.window != nil]; // animate once it's on screen
}

- (void)setEnabled:(BOOL)enabled {
	_enabled = enabled;
	[self layout:NO];
}

- (void)viewDidChangeEffectiveAppearance {
	[self layout:NO]; // light/dark: the off colour depends on it
}

- (void)layout:(BOOL)animated {
	NSRect r = self.bounds;
	CGFloat d = NSHeight(r) - 3;
	__block CGColorRef track, knob;
	[self.effectiveAppearance performAsCurrentDrawingAppearance:^{
		track = (self.on ? NSColor.systemGreenColor : [NSColor.labelColor colorWithAlphaComponent:0.16]).CGColor;
		knob = NSColor.whiteColor.CGColor;
	}];
	[CATransaction begin];
	[CATransaction setDisableActions:!animated];
	[CATransaction setAnimationDuration:0.18];
	[CATransaction setAnimationTimingFunction:[CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut]];
	_track.frame = r;
	_track.cornerRadius = NSHeight(r) / 2;
	_track.backgroundColor = track;
	_knob.frame = CGRectMake(self.on ? NSMaxX(r) - d - 1.5 : 1.5, 1.5, d, d);
	_knob.cornerRadius = d / 2;
	_knob.backgroundColor = knob;
	self.layer.opacity = self.enabled ? 1.0 : 0.45;
	[CATransaction commit];
}
@end

// A menu row with a label and a toggle. Clicking anywhere on it flips the
// toggle; clicks inside a menu item's own view don't close the menu.
@interface HTSwitchRow : NSView {
	@public NSInteger _rowTag;
}
@property (strong) HTToggle *toggle;
@property (strong) NSTextField *label;
@property (strong) NSVisualEffectView *highlight;
@end

@implementation HTSwitchRow
// Taking the mouse-down keeps the menu from treating the click as choosing
// the item, which would close it and send the click a second time.
- (void)mouseDown:(NSEvent *)event {}
- (void)mouseUp:(NSEvent *)event {
	if (!self.toggle.enabled) return;
	NSMenu *menu = systrayIvar("menu");
	NSMenuItem *item = [menu itemWithTag:self.tag];
	if (!item || !item.target) return;
	self.toggle.on = !self.toggle.on; // right away; the real state follows
	switchUsed = YES;
	// systray's menuHandler: reports the click to Go like a normal selection.
	[NSApp sendAction:item.action to:item.target from:item];
}
- (NSInteger)tag { return _rowTag; }

// Views in menu items show their own hover highlight; AppKit redraws the
// view when its item's highlight changes. The highlight uses the same
// "selection" material as ordinary menu items, so it looks identical.
- (void)viewWillDraw {
	[super viewWillDraw];
	NSMenuItem *item = self.enclosingMenuItem;
	BOOL hot = item.isHighlighted && item.isEnabled;
	self.highlight.hidden = !hot;
	NSColor *text = !item.isEnabled ? NSColor.disabledControlTextColor
		: hot ? NSColor.selectedMenuItemTextColor : NSColor.labelColor;
	if (![self.label.textColor isEqual:text]) self.label.textColor = text;
}
- (void)drawRect:(NSRect)dirty {}
@end

// The switch shows the state, so the item itself stays unchecked: macOS adds
// a checkmark column to the whole menu while any item is checked, which would
// shift the other items' text whenever a switch turns on or off.
static void clearState(NSMenuItem *item) {
	item.state = NSControlStateValueOff;
}

static void addSwitchRow(NSMenu *menu, NSInteger tag) {
	NSMenuItem *item = [menu itemWithTag:tag];
	if (!item) return;
	const CGFloat w = 240, h = 26, inset = 15, gap = 8; // inset matches item text without a checkmark column

	HTSwitchRow *row = [[HTSwitchRow alloc] initWithFrame:NSMakeRect(0, 0, w, h)];
	row.autoresizingMask = NSViewWidthSizable;

	NSVisualEffectView *hl = [[NSVisualEffectView alloc] initWithFrame:NSInsetRect(row.bounds, 5, 0)];
	hl.material = NSVisualEffectMaterialSelection;
	hl.state = NSVisualEffectStateActive;
	hl.emphasized = YES;
	hl.wantsLayer = YES;
	hl.layer.cornerRadius = 4;
	hl.layer.masksToBounds = YES;
	hl.autoresizingMask = NSViewWidthSizable;
	hl.hidden = YES;
	row.highlight = hl;
	[row addSubview:hl];

	HTToggle *sw = [[HTToggle alloc] initWithFrame:NSMakeRect(w - 28 - 14, round((h - 16) / 2), 28, 16)];
	NSRect sf = sw.frame;
	sw.autoresizingMask = NSViewMinXMargin;
	sw.on = item.state == NSControlStateValueOn;
	sw.enabled = item.enabled;
	row->_rowTag = tag;
	row.toggle = sw;

	NSTextField *label = [NSTextField labelWithString:item.title];
	label.font = [NSFont menuFontOfSize:0];
	label.textColor = item.enabled ? NSColor.labelColor : NSColor.disabledControlTextColor;
	label.lineBreakMode = NSLineBreakByTruncatingTail;
	[label sizeToFit];
	NSRect lf = label.frame;
	lf.origin = NSMakePoint(inset, round((h - lf.size.height) / 2));
	lf.size.width = sf.origin.x - inset - gap;
	label.frame = lf;
	label.autoresizingMask = NSViewWidthSizable;

	row.label = label;
	[row addSubview:label];
	[row addSubview:sw];
	row.toolTip = item.toolTip;
	item.view = row;
	clearState(item);
}

static void useSwitchRows(int *tags, int n) {
	onMain(^{
		NSMenu *menu = systrayIvar("menu");
		if (![menu isKindOfClass:[NSMenu class]]) return;
		for (int i = 0; i < n; i++) addSwitchRow(menu, tags[i]);
	});
}

// Moves existing switches to a new state. The items' own checked state is
// never touched (see clearState).
static void setSwitchRows(int *tags, int *on, int n) {
	onMain(^{
		NSMenu *menu = systrayIvar("menu");
		if (![menu isKindOfClass:[NSMenu class]]) return;
		for (int i = 0; i < n; i++) {
			NSMenuItem *item = [menu itemWithTag:tags[i]];
			if (![item.view isKindOfClass:[HTSwitchRow class]]) continue;
			((HTSwitchRow *)item.view).toggle.on = on[i] != 0;
		}
	});
}

// Opens the tray menu again after a normal menu item closed it. Clicking the
// status button from code doesn't show the menu outside a real mouse event,
// so pop the menu up directly. The menu has already been rebuilt (systray's
// updates wait for the main thread), and queuing behind systray's own close
// handling is all the waiting needed.
static void reopenTrayMenu(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (switchUsed) { // the menu never closed
			switchUsed = NO;
			return;
		}
		NSStatusItem *item = systrayIvar("statusItem");
		NSMenu *menu = systrayIvar("menu");
		if (![item isKindOfClass:[NSStatusItem class]] || ![menu isKindOfClass:[NSMenu class]]) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		[item popUpStatusItemMenu:menu];
#pragma clang diagnostic pop
	});
}
*/
import "C"

import (
	"reflect"
	"unsafe"

	"fyne.io/systray"
)

// On macOS the proxy and group rows get real switches. Flipping one doesn't
// close the menu, so several can be changed in a row. If the menu did close
// anyway (keyboard selection), reopenMenu brings it back.

func watchMenu() {}

// reopenMenu shows the tray menu again unless it is still open.
func reopenMenu() { C.reopenTrayMenu() }

// useSwitches turns these menu items into rows with a switch.
func useSwitches(items []*systray.MenuItem) {
	if tags := itemTags(items); len(tags) > 0 {
		C.useSwitchRows((*C.int)(unsafe.Pointer(&tags[0])), C.int(len(tags)))
	}
}

// setSwitches moves switches without marking their items checked: a checked
// item makes macOS widen the open menu for a checkmark column, and the menu
// jumps sideways.
func setSwitches(items []*systray.MenuItem, on []bool) {
	tags := itemTags(items)
	if len(tags) == 0 || len(tags) != len(on) {
		return
	}
	states := make([]C.int, len(on))
	for i, v := range on {
		if v {
			states[i] = 1
		}
	}
	C.setSwitchRows((*C.int)(unsafe.Pointer(&tags[0])), (*C.int)(unsafe.Pointer(&states[0])), C.int(len(tags)))
}

// itemTags returns the NSMenuItem tags: systray keeps an item's id private,
// and uses it as the tag.
func itemTags(items []*systray.MenuItem) []C.int {
	tags := make([]C.int, 0, len(items))
	for _, item := range items {
		if item != nil {
			tags = append(tags, C.int(reflect.ValueOf(item).Elem().FieldByName("id").Uint()))
		}
	}
	return tags
}
