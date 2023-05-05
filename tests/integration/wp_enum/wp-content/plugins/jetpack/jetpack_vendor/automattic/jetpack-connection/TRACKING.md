# Jetpack Tracking package

A package containing functionality to track events to the a8c Tracks system

## Usage

There are several ways to track events using this package.

* Ajax: Probably the easiest one. You can simply add a class to a link and it will be tracked or you can make your own ajax call
* PHP: Track an event on the backend
* Tracking pixel: An alternative way to track events by dynamically adding a pixel to the DOM

### Tracking via Ajax

This is useful to track simple click events without the need of any additional js. Just add the appropriate class to your links and it will be tracked.

#### 1. enqueue script

Note: Not needed if you are using the Jetpack plugin in the admin context as the script is already loaded by Jetpack.

See `Automattic\Jetpack\Tracking::enqueue_tracks_scripts()`

```PHP
add_action( 'admin_enqueue_scripts', array( new Tracking( 'plugin-slug' ), 'enqueue_tracks_scripts' ) );
```

#### 2. Add the class and the event attributes.

Add the `jptracks` class to any `a` element or to its parent element.

The event needs a name. This can be informed with the `data-jptracks-name` attritbute.

```HTML
<a class="jptracks" data-jptracks-name="my-awesome-event">Click me</a>
```

And that's it. Your event will be tracked. Every time this element is clicked an ajax call will be triggered to the Tracking package and it will send it to wpcom.

**Note:** Event name will be automatically prefixed with `jetpack_`.

#### 3. Additional parameters

You can also inform additional parameters to your event using the `data-jptracks-prop` attribute. Anything in this attr will be stored in the `clicked` attribute in the event.

#### 4. Making your own ajax calls

In your JS you can set up your own ajax calls. Example:

```JS
window.jpTracksAJAX.record_ajax_event( 'my_event_name', 'click', { prop1: value1, prop2: value2 } );
```

**Note:** Event name will be automatically prefixed with `jetpack_`.

##### Waiting for the ajax call to complete before doing anything else

If you need to do a subsequent action but wants to wait for this event to be tracked, you can do the following:

```JS
window.jpTracksAJAX
	.record_ajax_event( 'my_event_name', 'click', { prop1: value1, prop2: value2 }  )
	.always( function() {
		// do something
	} );
```

### Tracking in PHP

Use `Automattic\Jetpack\Tracking::record_user_event()` to track events on the backend.

```PHP
$connection_manager = new Automattic\Jetpack\Connection\Manager( 'plugin-slug' );
$tracking           = new Tracking( 'plugin-slug', $connection_manager );
$tracking->record_user_event(
	$event_name,
	array(
		'property_key' => 'value',
	)
);
```

### Tracking pixel

This approach to track events uses `//stats.wp.com/w.js` and dynamically adds a tracking pixel to the DOM to do the tracking.

#### 1. Enqueue the scripts

```PHP
Tracking::register_tracks_functions_scripts( true );
```

#### 2. Inform the user data

```PHP
wp_localize_script(
	'my_script',
	'varname',
	array(
		'tracksUserData'   => Jetpack_Tracks_Client::get_connected_user_tracks_identity(),
	)
);
```

#### 3. Track!

In your JS:

```JS
var tracksUser = varname.tracksUserData;

analytics.initialize( tracksUser.userid, tracksUser.username );

analytics.tracks.recordEvent( 'jetpack_my_event_name', { prop1: value1, prop2: value2 } );
```

## Debugging

You can watch your events being tracked in the browser console. In order to activate that, run the following command in the console:

```JS
localStorage.setItem( 'debug', 'dops:analytics*' );
```
