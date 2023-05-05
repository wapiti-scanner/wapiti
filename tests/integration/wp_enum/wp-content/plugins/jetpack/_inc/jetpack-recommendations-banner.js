/* global jp_banner */

( function ( $ ) {
	var recommendationsBanner = $( '#jp-recommendations-banner-main' );
	var recommendationsBannerForm = $( '#jp-recommendations-banner__form' );
	var recommendationsBannerContinue = $( '#jp-recommendations-banner__continue-button' );
	var recommendationsBannerDismiss = $( '#jp-recommendations-banner__notice-dismiss' );

	recommendationsBannerForm.on( 'change', function ( event ) {
		if (
			'checkbox' === event.target.type &&
			event.target.parentElement &&
			'label' === event.target.parentElement.tagName.toLowerCase()
		) {
			var isChecked = $( 'label.checked input[name="' + event.target.name + '"]' ).length > 0;
			if ( isChecked ) {
				event.target.parentElement.classList.remove( 'checked' );
			} else {
				event.target.parentElement.classList.add( 'checked' );
			}
		}
	} );

	recommendationsBannerContinue.on( 'click', function () {
		var fieldNames = [ 'builder', 'store', 'personal' ];
		var formData = {};
		fieldNames.forEach( function ( name ) {
			formData[ name ] = $( "input[name='" + name + "']" ).prop( 'checked' );
		} );
		$.post(
			jp_banner.ajax_url,
			{
				action: 'jetpack_recommendations_banner',
				nonce: jp_banner.nonce,
				personal: formData.personal,
				builder: formData.builder,
				store: formData.store,
			},
			function ( response ) {
				if ( true === response.success ) {
					window.location.assign( jp_banner.recommendations_url );
				}
			}
		);
	} );

	recommendationsBannerDismiss.on( 'click', function () {
		$( recommendationsBanner ).hide();

		var data = {
			action: 'jetpack_recommendations_banner',
			nonce: jp_banner.nonce,
			dismissBanner: true,
		};

		$.post( jp_banner.ajax_url, data, function ( response ) {
			if ( true !== response.success ) {
				$( recommendationsBanner ).show();
			}
		} );
	} );
} )( jQuery );
