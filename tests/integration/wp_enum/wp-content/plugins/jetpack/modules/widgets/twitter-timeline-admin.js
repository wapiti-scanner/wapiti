jQuery( function ( $ ) {
	function twitterWidgetTypeChanged( widgetTypeSelector ) {
		var selectedType = $( widgetTypeSelector ).val();
		$( widgetTypeSelector )
			.closest( '.jetpack-twitter-timeline-widget-type-container' )
			.next( '.jetpack-twitter-timeline-widget-id-container' )
			.find( 'label' )
			.css( 'display', function () {
				var labelType = $( this ).data( 'widget-type' );
				if ( selectedType === labelType ) {
					return '';
				} else {
					return 'none';
				}
			} );
	}

	function twitterWidgetTweetDisplayChanged( event ) {
		var $tweetDisplaySelector = $( event.target );
		var selectedTweetDisplay = $tweetDisplaySelector.val();
		var $form = $tweetDisplaySelector.closest( 'form' );
		var $heightContainer = $form.find( '.jetpack-twitter-timeline-widget-height-container' );
		var $tweetLimitContainer = $form.find(
			'.jetpack-twitter-timeline-widget-tweet-limit-container'
		);
		var $scrollbarInput = $form.find( 'input[id*=chrome-noscrollbar]' );
		switch ( selectedTweetDisplay ) {
			case 'fixed':
				$heightContainer.hide();
				$tweetLimitContainer.show();
				$scrollbarInput.prop( 'disabled', true );
				break;
			case 'dynamic':
				$tweetLimitContainer.hide();
				$heightContainer.show();
				$scrollbarInput.prop( 'disabled', false );
				break;
		}
	}

	// We could either be in wp-admin/widgets.php or the Customizer.
	var $container = $( '#customize-controls' );
	if ( ! $container.length ) {
		$container = $( '#wpbody' );
	}

	// Observe widget settings for 'change' events of the 'type' property for
	// current and future Twitter timeline widgets.
	$container.on( 'change', '.jetpack-twitter-timeline-widget-type', function () {
		twitterWidgetTypeChanged( this );
	} );

	// Set the labels for currently existing widgets (including the "template"
	// version that is copied when a new widget is added).
	$container.find( '.jetpack-twitter-timeline-widget-type' ).each( function () {
		twitterWidgetTypeChanged( this );
	} );

	// Observe widget settings for 'change' events of the 'tweet-display' property for
	// current and future Twitter timeline widgets.
	$container.on(
		'change',
		'.jetpack-twitter-timeline-widget-tweet-display-radio',
		twitterWidgetTweetDisplayChanged
	);
} );
