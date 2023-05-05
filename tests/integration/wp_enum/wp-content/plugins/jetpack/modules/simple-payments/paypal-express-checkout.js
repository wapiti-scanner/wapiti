/**
 * This PaypalExpressCheckout global is included by wp_enqueue_script( 'jetpack-paypal-express-checkout' );
 * It handles communication with Paypal Express checkout and public-api.wordpress.com for the purposes
 * of simple-payments module.
 */

/* global paypal */
/* exported PaypalExpressCheckout */
var PaypalExpressCheckout = {
	primaryCssClassName: 'jetpack-simple-payments',
	messageCssClassName: 'jetpack-simple-payments-purchase-message',

	wpRestAPIHost: 'https://public-api.wordpress.com',
	wpRestAPIVersion: '/wpcom/v2',

	getEnvironment: function () {
		if (
			localStorage &&
			localStorage.getItem &&
			localStorage.getItem( 'simple-payments-env' ) === 'sandbox'
		) {
			return 'sandbox';
		}
		return 'production';
	},

	getCreatePaymentEndpoint: function ( blogId ) {
		return (
			PaypalExpressCheckout.wpRestAPIHost +
			PaypalExpressCheckout.wpRestAPIVersion +
			'/sites/' +
			blogId +
			'/simple-payments/paypal/payment'
		);
	},

	getExecutePaymentEndpoint: function ( blogId, paymentId ) {
		return (
			PaypalExpressCheckout.wpRestAPIHost +
			PaypalExpressCheckout.wpRestAPIVersion +
			'/sites/' +
			blogId +
			'/simple-payments/paypal/' +
			paymentId +
			'/execute'
		);
	},

	getNumberOfItems: function ( field, enableMultiple ) {
		if ( enableMultiple !== '1' ) {
			return 1;
		}

		var numberField = document.getElementById( field );

		if ( ! numberField ) {
			return 1;
		}

		var number = Number( numberField.value );

		if ( isNaN( number ) ) {
			return 1;
		}
		return number;
	},

	/**
	 * Get the DOM element-placeholder used to show message
	 * about the transaction. If it doesn't exist then the function will create a new one.
	 *
	 * @param  string domId id of the payment button placeholder
	 * @return Element the dom element to print the message
	 */
	getMessageContainer: function ( domId ) {
		return document.getElementById( domId + '-message-container' );
	},

	/**
	 * Show a messange close to the Paypal button.
	 * Use this function to give feedback to the user according
	 * to the transaction result.
	 *
	 * @param  {String} message message to show
	 * @param  {String} domId paypal-button element dom identifier
	 * @param  {Boolean} [error] defines if it's a message error. Not TRUE as default.
	 */
	showMessage: function ( message, domId, isError ) {
		var domEl = PaypalExpressCheckout.getMessageContainer( domId );

		// set css classes
		var cssClasses = PaypalExpressCheckout.messageCssClassName + ' show ';
		cssClasses += isError ? 'error' : 'success';

		// show message 1s after PayPal popup is closed
		setTimeout( function () {
			domEl.innerHTML = message;
			domEl.setAttribute( 'class', cssClasses );
		}, 1000 );
	},

	showError: function ( message, domId ) {
		PaypalExpressCheckout.showMessage( message, domId, true );
	},

	processErrorMessage: function ( errorResponse ) {
		var error = errorResponse ? errorResponse.responseJSON : null;
		var defaultMessage = 'There was an issue processing your payment.';

		if ( ! error ) {
			return '<p>' + defaultMessage + '</p>';
		}

		if ( error.additional_errors ) {
			var messages = [];
			error.additional_errors.forEach( function ( additionalError ) {
				if ( additionalError.message ) {
					messages.push( '<p>' + additionalError.message.toString() + '</p>' );
				}
			} );
			return messages.join( '' );
		}

		return '<p>' + ( error.message || defaultMessage ) + '</p>';
	},

	processSuccessMessage: function ( successResponse ) {
		var message = successResponse.message;
		var defaultMessage = 'Thank you. Your purchase was successful!';

		if ( ! message ) {
			return '<p>' + defaultMessage + '</p>';
		}

		return '<p>' + message + '</p>';
	},

	cleanAndHideMessage: function ( domId ) {
		var domEl = PaypalExpressCheckout.getMessageContainer( domId );
		domEl.setAttribute( 'class', PaypalExpressCheckout.messageCssClassName );
		domEl.innerHTML = '';
	},

	renderButton: function ( blogId, buttonId, domId, enableMultiple ) {
		var env = PaypalExpressCheckout.getEnvironment();

		if ( ! paypal ) {
			throw new Error( 'PayPal module is required by PaypalExpressCheckout' );
		}

		var buttonDomId = domId + '_button';

		paypal.Button.render(
			{
				env: env,
				commit: true,

				style: {
					label: 'pay',
					shape: 'rect',
					color: 'silver',
					size: 'responsive',
					fundingicons: true,
				},

				payment: function () {
					PaypalExpressCheckout.cleanAndHideMessage( domId );

					var payload = {
						number: PaypalExpressCheckout.getNumberOfItems( domId + '_number', enableMultiple ),
						buttonId: buttonId,
						env: env,
					};

					return new paypal.Promise( function ( resolve, reject ) {
						jQuery
							.post( PaypalExpressCheckout.getCreatePaymentEndpoint( blogId ), payload )
							.done( function ( paymentResponse ) {
								if ( ! paymentResponse ) {
									PaypalExpressCheckout.showError(
										PaypalExpressCheckout.processErrorMessage(),
										domId
									);
									return reject( new Error( 'server_error' ) );
								}

								resolve( paymentResponse.id );
							} )
							.fail( function ( paymentError ) {
								var paymentErrorMessage = PaypalExpressCheckout.processErrorMessage( paymentError );
								PaypalExpressCheckout.showError( paymentErrorMessage, domId );

								var code =
									paymentError.responseJSON && paymentError.responseJSON.code
										? paymentError.responseJSON.code
										: 'server_error';

								reject( new Error( code ) );
							} );
					} );
				},

				onAuthorize: function ( onAuthData ) {
					var payload = {
						buttonId: buttonId,
						payerId: onAuthData.payerID,
						env: env,
					};
					return new paypal.Promise( function ( resolve, reject ) {
						jQuery
							.post(
								PaypalExpressCheckout.getExecutePaymentEndpoint( blogId, onAuthData.paymentID ),
								payload
							)
							.done( function ( authResponse ) {
								if ( ! authResponse ) {
									PaypalExpressCheckout.showError(
										PaypalExpressCheckout.processErrorMessage(),
										domId
									);
									return reject( new Error( 'server_error' ) );
								}

								PaypalExpressCheckout.showMessage(
									PaypalExpressCheckout.processSuccessMessage( authResponse ),
									domId
								);
								resolve();
							} )
							.fail( function ( authError ) {
								var authErrorMessage = PaypalExpressCheckout.processErrorMessage( authError );
								PaypalExpressCheckout.showError( authErrorMessage, domId );

								var code =
									authError.responseJSON && authError.responseJSON.code
										? authError.responseJSON.code
										: 'server_error';

								reject( new Error( code ) );
							} );
					} );
				},
			},
			buttonDomId
		);
	},
};
