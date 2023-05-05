/* global ajaxurl */
/**
 * WPForms Challenge function.
 *
 * @since 1.5.0
 * @since 1.6.2 Challenge v2.
 */
'use strict';

var WPFormsChallenge = window.WPFormsChallenge || {};

WPFormsChallenge.embed = window.WPFormsChallenge.embed || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.5.0
		 */
		init: function() {

			$( app.ready );
			$( window ).on( 'load', function() {

				// in case of jQuery 3.+ we need to wait for an `ready` event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.5.0
		 */
		ready: function() {

			app.setup();
			app.events();
			app.observeFullscreenMode();
		},

		/**
		 * Window load.
		 *
		 * @since 1.5.0
		 */
		load: function() {

			// If the page is Add new page.
			if ( window.location.href.indexOf( 'post-new.php' ) > -1 ) {
				app.lastStep();
				$( '.wpforms-challenge-dot-completed' ).hide();

				return;
			}

			if ( WPFormsChallenge.core.isGutenberg() ) {
				WPFormsChallenge.core.initTooltips( 5, '.block-editor .edit-post-header', { side: 'bottom' } );
				app.updateTooltipVisibility();
			} else {
				WPFormsChallenge.core.initTooltips( 5, '.wpforms-insert-form-button', { side: 'right' } );
			}

			WPFormsChallenge.core.updateTooltipUI();
		},

		/**
		 * Initial setup.
		 *
		 * @since 1.5.0
		 */
		setup: function() {

			if ( 5 === WPFormsChallenge.core.loadStep() ) {
				$( '.wpforms-challenge' ).addClass( 'wpforms-challenge-completed' );
				app.showPopup();
			}

			$( '.wpforms-challenge' ).show();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.5.0
		 */
		events: function() {

			$( '.wpforms-challenge-step5-done' )
				.on( 'click', app.lastStep );

			$( '.wpforms-challenge-popup-close, .wpforms-challenge-end' )
				.on( 'click', app.completeChallenge );

			$( '#wpforms-challenge-contact-form .wpforms-challenge-popup-contact-btn' )
				.on( 'click', app.submitContactForm );
		},

		/**
		 * Last step done routine.
		 *
		 * @since 1.6.2
		 */
		lastStep: function() {

			WPFormsChallenge.core.timer.pause();
			WPFormsChallenge.core.stepCompleted( 5 );
			$( '.wpforms-challenge' ).addClass( 'wpforms-challenge-completed' );
			app.showPopup();
		},

		/**
		 * Show either 'Congratulations' or 'Contact Us' popup.
		 *
		 * @since 1.5.0
		 */
		showPopup: function() {

			var secondsLeft = WPFormsChallenge.core.timer.getSecondsLeft();

			$( '.wpforms-challenge-popup-container' ).show();

			if ( 0 < secondsLeft ) {
				var secondsSpent = WPFormsChallenge.core.timer.getSecondsSpent( secondsLeft );

				$( '#wpforms-challenge-congrats-minutes' )
					.text( WPFormsChallenge.core.timer.getMinutesFormatted( secondsSpent ) );
				$( '#wpforms-challenge-congrats-seconds' )
					.text( WPFormsChallenge.core.timer.getSecondsFormatted( secondsSpent ) );
				$( '#wpforms-challenge-congrats-popup' ).show();
			} else {
				$( '#wpforms-challenge-contact-popup' ).show();
			}
		},

		/**
		 * Hide the popup.
		 *
		 * @since 1.5.0
		 */
		hidePopup: function() {

			$( '.wpforms-challenge-popup-container' ).hide();
			$( '.wpforms-challenge-popup' ).hide();
		},

		/**
		 * Complete Challenge.
		 *
		 * @since 1.5.0
		 */
		completeChallenge: function() {

			var optionData = {
				status       : 'completed',
				seconds_spent: WPFormsChallenge.core.timer.getSecondsSpent(),
				seconds_left : WPFormsChallenge.core.timer.getSecondsLeft(),
			};

			app.hidePopup();

			WPFormsChallenge.core.removeChallengeUI();
			WPFormsChallenge.core.clearLocalStorage();

			WPFormsChallenge.admin.saveChallengeOption( optionData )
				.done( WPFormsChallenge.core.triggerPageSave ); // Save and reload the page to remove WPForms Challenge JS.
		},

		/**
		 * Submit contact form button click event handler.
		 *
		 * @since 1.5.0
		 *
		 * @param {object} e Event object.
		 */
		submitContactForm: function( e ) {

			e.preventDefault();

			var $btn = $( this ),
				$form = $btn.closest( '#wpforms-challenge-contact-form' );

			/* eslint-disable camelcase */
			var data = {
				action      : 'wpforms_challenge_send_contact_form',
				_wpnonce    : WPFormsChallenge.admin.l10n.nonce,
				contact_data: {
					message   : $form.find( '.wpforms-challenge-contact-message' ).val(),
					contact_me: $form.find( '.wpforms-challenge-contact-permission' ).prop( 'checked' ),
				},
			};
			/* eslint-enable */

			$btn.prop( 'disabled', true );

			$.post( ajaxurl, data, function( response ) {

				if ( ! response.success ) {
					console.error( 'Error sending WPForms Challenge Contact Form.' );
				}
			} ).done( app.completeChallenge );
		},

		/**
		 * Observe Gutenberg's Fullscreen Mode state to adjust tooltip positioning.
		 *
		 * @since 1.6.2
		 */
		observeFullscreenMode: function() {

			var $body = $( 'body' ),
				isFullScreenPrev = $body.hasClass( 'is-fullscreen-mode' );

			// MutationObserver configuration and callback.
			var obs = {
				targetNode  : $body[0],
				config      : {
					attributes: true,
				},
			};

			obs.callback = function( mutationsList, observer ) {

				var mutation,
					isFullScreen,
					$step5 = $( '.wpforms-challenge-tooltip-step5' ),
					$step5Arrow = $step5.find( '.tooltipster-arrow' );

				for ( var i in mutationsList ) {
					mutation = mutationsList[ i ];
					if ( mutation.type !== 'attributes' || mutation.attributeName !== 'class' ) {
						continue;
					}

					isFullScreen = $body.hasClass( 'is-fullscreen-mode' );
					if ( isFullScreen === isFullScreenPrev ) {
						continue;
					}
					isFullScreenPrev = isFullScreen;

					if ( isFullScreen ) {
						$step5.css( {
							'top': '93px',
							'left': '0',
						} );
						$step5Arrow.css( 'left', '91px' );
					} else {
						$step5.css( {
							'top': '125px',
							'left': '66px',
						} );
						$step5Arrow.css( 'left', '130px' );
					}
				}
			};

			obs.observer = new MutationObserver( obs.callback );
			obs.observer.observe( obs.targetNode, obs.config );
		},

		/**
		 * Update tooltip z-index when Gutenberg sidebar is open.
		 *
		 * @since 1.7.4
		 *
		 * @returns {Function} Default function.
		 */
		updateTooltipVisibility: function() {

			var targetNode = document.querySelector( '.interface-interface-skeleton__body' );

			if ( targetNode === null ) {
				return app.updateTooltipVisibilityDefault();
			}

			var observer = new MutationObserver( function( mutationsList ) {

				var $step5 = $( '.wpforms-challenge-tooltip-step5' );

				for ( var mutation of mutationsList ) {

					if ( mutation.type === 'childList' ) {
						$step5.toggleClass( 'wpforms-challenge-tooltip-step5-hide' );
					}
				}
			} );

			observer.observe( targetNode, { attributes: true, childList: true } );
		},

		/**
		 * Update tooltip visibility for WP 5.6 version.
		 *
		 * @since 1.7.4
		 */
		updateTooltipVisibilityDefault: function() {

			$( '.editor-inserter__toggle' ).on( 'click', function() {

				$( '.wpforms-challenge-tooltip-step5' ).toggleClass( 'wpforms-challenge-tooltip-step5-hide' );
			} );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsChallenge.embed.init();
