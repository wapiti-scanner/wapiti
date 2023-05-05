( function ( $ ) {
	// We could either be in wp-admin/widgets.php or the customizer.
	var $container = $( '#customize-controls' );

	if ( ! $container.length ) {
		$container = $( '#wpbody' );
	}

	$container.on( 'change', '.milestone-type', function () {
		var $messageWrapper = $( this ).parent().find( '.milestone-message-wrapper' );

		$( this ).find( 'input[type="radio"]:checked' ).val() === 'since'
			? $messageWrapper.hide()
			: $messageWrapper.show();
	} );

	function triggerChange() {
		$container.find( '.milestone-type' ).trigger( 'change' );
	}

	// Used when adding widget via customizer or saving settings.
	$( document ).on( 'widget-added widget-updated', function () {
		triggerChange();
	} );

	triggerChange();
} )( jQuery );
