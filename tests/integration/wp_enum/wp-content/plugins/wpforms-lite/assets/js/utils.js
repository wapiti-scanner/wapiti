'use strict';

// eslint-disable-next-line no-unused-vars
const WPFormsUtils = window.WPFormsUtils || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.6
	 *
	 * @type {object}
	 */
	const app = {

		/**
		 * Wrapper to trigger a native or custom event and return the event object.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $element  Element to trigger event on.
		 * @param {string} eventName Event name to trigger (custom or native).
		 * @param {Array}  args      Trigger arguments.
		 *
		 * @returns {Event} Event object.
		 */
		triggerEvent: function( $element, eventName, args = [] ) {

			let eventObject = new $.Event( eventName );

			$element.trigger( eventObject, args );

			return eventObject;
		},

		/**
		 * Debounce.
		 *
		 * This function comes directly from underscore.js:
		 *
		 * Returns a function, that, as long as it continues to be invoked, will not
		 * be triggered. The function will be called after it stops being called for
		 * N milliseconds. If `immediate` is passed, trigger the function on the
		 * leading edge, instead of the trailing.
		 *
		 * Debouncing is removing unwanted input noise from buttons, switches or other user input.
		 * Debouncing prevents extra activations or slow functions from triggering too often.
		 *
		 * @param {Function} func      The function to be debounced.
		 * @param {int}      wait      The amount of time to delay calling func.
		 * @param {bool}     immediate Whether or not to trigger the function on the leading edge.
		 *
		 * @returns {Function} Returns a function that, as long as it continues to be invoked, will not be triggered.
		 */
		debounce: function( func, wait, immediate ) {

			var timeout;

			return function() {

				var context = this,
					args = arguments;
				var later = function() {

					timeout = null;

					if ( ! immediate ) {
						func.apply( context, args );
					}
				};

				var callNow = immediate && ! timeout;

				clearTimeout( timeout );

				timeout = setTimeout( later, wait );

				if ( callNow ) {
					func.apply( context, args );
				}
			};
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );
