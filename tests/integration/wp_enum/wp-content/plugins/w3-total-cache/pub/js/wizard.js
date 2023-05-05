/**
 * File: wizard.js
 *
 * JavaScript for the wizard.
 *
 * @since 2.0.0
 */

 jQuery(function() {
	var $container = jQuery( '#w3tc-wizard-container'),
		$skipLink = $container.find( '#w3tc-wizard-skip-link '),
		$skipButton = $container.find( '#w3tc-wizard-skip '),
		$nextButton = $container.find( '#w3tc-wizard-next '),
		$previousButton = $container.find( '#w3tc-wizard-previous ');

	jQuery( '.button-buy-plugin' ).parent().remove();

	$skipLink.on( 'click', skipFunction );
	$skipButton.on( 'click', skipFunction );

	jQuery( window ).on( 'beforeunload', function() {
		return W3TC_Wizard.beforeunloadText;
	});

	// Listen for clicks to go to the W3TC Dashboard.
	$container.find( '#w3tc-wizard-dashboard' ).on( 'click', function () {
		jQuery( window ).off( 'beforeunload' );
		document.location = W3TC_SetupGuide.dashboardUrl;
	});

	/**
	 * Process the skip action.
	 *
	 * Saves and option to mark the wizard completed.
	 *
	 * @since 2.0.0
	 */
	function skipFunction() {
		var $this = jQuery( this ),
			nodeName = $this.prop('nodeName'),
			page = location.href.replace(/^.+page=/, '' );

		jQuery( window ).off( 'beforeunload' );

		if ( 'BUTTON' === nodeName ) {
			$this
				.prop( 'disabled', true )
				.css( 'color', '#000' )
				.text( 'Skipping...' );
		}

		// GA.
		if ( window.w3tc_ga ) {
			w3tc_ga( 'send', 'event', 'button', page, 'skip' );
		}

		jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: $container.find( '[name="_wpnonce"]' ).val(),
				action: "w3tc_wizard_skip"
			}
		})
			.done(function( response ) {
				if ( 'BUTTON' === nodeName ) {
					$this.text( 'Redirecting...' );
				}

				window.location.replace( location.href.replace(/page=.+$/, 'page=w3tc_dashboard') );
			})
			.fail(function() {
				if ( 'BUTTON' === nodeName ) {
					$this.text( 'Error with Ajax; reloading page...' );
				}

				location.reload();
			});
	};

	$previousButton.on( 'click', function() {
		var $currentSlide = $container.find( '.w3tc-wizard-slides:visible' ),
			$previousSlide = $currentSlide.prev( '.w3tc-wizard-slides' );

		if ( $previousSlide.length ) {
			$currentSlide.hide();
			$previousSlide.show();
			$nextButton.prop( 'disabled', false );
		}

		// Hide the previous button and show the skip button on the first slide.
		if ( 0 === $previousSlide.prev( '.w3tc-wizard-slides' ).length ) {
			$previousButton.closest( 'span' ).hide();
			$skipButton.closest( 'span' ).show();
		}

		w3tc_wizard_actions( $previousSlide );
	});

	$nextButton.on( 'click', function() {
		var $currentSlide = $container.find( '.w3tc-wizard-slides:visible' ),
			$nextSlide = $currentSlide.next( '.w3tc-wizard-slides' );

		if ( $skipButton.is( ':visible' ) ) {
			$skipButton.closest( 'span' ).hide();
			$previousButton.closest( 'span' ).show();
		}

		if ( $nextSlide.length ) {
			$currentSlide.hide();
			$nextSlide.show();
		}

		// Disable the next button on the last slide.
		if ( 0 === $nextSlide.next( '.w3tc-wizard-slides' ).length ) {
			jQuery( this ).prop( 'disabled', 'disabled' );
		}

		w3tc_wizard_actions( $nextSlide );
	});
});
