/* global wpforms_admin, WPFormsAdmin */

/**
 * WPForms Admin Notifications.
 *
 * @since 1.6.0
 */

'use strict';

var WPFormsAdminNotifications = window.WPFormsAdminNotifications || ( function( document, window, $ ) {

	/**
	 * Elements holder.
	 *
	 * @since 1.6.0
	 *
	 * @type {object}
	 */
	var el = {

		$notifications:    $( '#wpforms-notifications' ),
		$nextButton:       $( '#wpforms-notifications .navigation .next' ),
		$prevButton:       $( '#wpforms-notifications .navigation .prev' ),
		$adminBarCounter:  $( '#wp-admin-bar-wpforms-menu .wpforms-menu-notification-counter' ),
		$adminBarMenuItem: $( '#wp-admin-bar-wpforms-notifications' ),

	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.6.0
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.6.0
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.6.0
		 */
		ready: function() {

			app.updateNavigation();
			app.events();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.6.0
		 */
		events: function() {

			el.$notifications
				.on( 'click', '.dismiss', app.dismiss )
				.on( 'click', '.next', app.navNext )
				.on( 'click', '.prev', app.navPrev );
		},

		/**
		 * Click on the Dismiss notification button.
		 *
		 * @since 1.6.0
		 *
		 * @param {object} event Event object.
		 */
		dismiss: function( event ) {

			if ( el.$currentMessage.length === 0 ) {
				return;
			}

			// Update counter.
			var count = parseInt( el.$adminBarCounter.text(), 10 );
			if ( count > 1 ) {
				--count;
				el.$adminBarCounter.html( count );
			} else {
				el.$adminBarCounter.remove();
				el.$adminBarMenuItem.remove();
			}

			// Remove notification.
			var $nextMessage = el.$nextMessage.length < 1 ? el.$prevMessage : el.$nextMessage,
				messageId = el.$currentMessage.data( 'message-id' );

			if ( $nextMessage.length === 0 ) {
				el.$notifications.remove();
			} else {
				el.$currentMessage.remove();
				$nextMessage.addClass( 'current' );
				app.updateNavigation();
			}

			// AJAX call - update option.
			var data = {
				action: 'wpforms_notification_dismiss',
				nonce: wpforms_admin.nonce,
				id: messageId,
			};

			$.post( wpforms_admin.ajax_url, data, function( res ) {

				if ( ! res.success ) {
					WPFormsAdmin.debug( res );
				}
			} ).fail( function( xhr, textStatus, e ) {

				WPFormsAdmin.debug( xhr.responseText );
			} );
		},

		/**
		 * Click on the Next notification button.
		 *
		 * @since 1.6.0
		 *
		 * @param {object} event Event object.
		 */
		navNext: function( event ) {

			if ( el.$nextButton.hasClass( 'disabled' ) ) {
				return;
			}

			el.$currentMessage.removeClass( 'current' );
			el.$nextMessage.addClass( 'current' );

			app.updateNavigation();
		},

		/**
		 * Click on the Previous notification button.
		 *
		 * @since 1.6.0
		 *
		 * @param {object} event Event object.
		 */
		navPrev: function( event ) {

			if ( el.$prevButton.hasClass( 'disabled' ) ) {
				return;
			}

			el.$currentMessage.removeClass( 'current' );
			el.$prevMessage.addClass( 'current' );

			app.updateNavigation();
		},

		/**
		 * Update navigation buttons.
		 *
		 * @since 1.6.0
		 */
		updateNavigation: function() {

			el.$currentMessage = el.$notifications.find( '.wpforms-notifications-message.current' );
			el.$nextMessage = el.$currentMessage.next( '.wpforms-notifications-message' );
			el.$prevMessage = el.$currentMessage.prev( '.wpforms-notifications-message' );

			if ( el.$nextMessage.length === 0 ) {
				el.$nextButton.addClass( 'disabled' );
			} else {
				el.$nextButton.removeClass( 'disabled' );
			}

			if ( el.$prevMessage.length === 0 ) {
				el.$prevButton.addClass( 'disabled' );
			} else {
				el.$prevButton.removeClass( 'disabled' );
			}
		},
	};

	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsAdminNotifications.init();
