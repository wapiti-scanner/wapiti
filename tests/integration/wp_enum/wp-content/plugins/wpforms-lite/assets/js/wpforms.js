/* global wpforms_settings, grecaptcha, hcaptcha, turnstile, wpformsRecaptchaCallback, wpformsRecaptchaV3Execute, wpforms_validate, wpforms_datepicker, wpforms_timepicker, Mailcheck, Choices, WPFormsPasswordField, WPFormsEntryPreview, punycode, tinyMCE, WPFormsUtils */

'use strict';

var wpforms = window.wpforms || ( function( document, window, $ ) {

	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.2.3
		 */
		init: function() {

			// Document ready.
			$( app.ready );

			// Page load.
			$( window ).on( 'load', function() {

				// In the case of jQuery 3.+, we need to wait for a ready event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );

			app.bindUIActions();
			app.bindOptinMonster();
		},

		/**
		 * Document ready.
		 *
		 * @since 1.2.3
		 */
		ready: function() {

			// Clear URL - remove wpforms_form_id.
			app.clearUrlQuery();

			// Set user identifier.
			app.setUserIndentifier();

			app.loadValidation();
			app.loadDatePicker();
			app.loadTimePicker();
			app.loadInputMask();
			app.loadSmartPhoneField();
			app.loadPayments();
			app.loadMailcheck();
			app.loadChoicesJS();

			// Randomize elements.
			$( '.wpforms-randomize' ).each( function() {
				var $list      = $( this ),
					$listItems = $list.children();
				while ( $listItems.length ) {
					$list.append( $listItems.splice( Math.floor( Math.random() * $listItems.length ), 1 )[0] );
				}
			} );

			// Unlock pagebreak navigation.
			$( '.wpforms-page-button' ).prop( 'disabled', false );

			$( document ).trigger( 'wpformsReady' );
		},

		/**
		 * Page load.
		 *
		 * @since 1.2.3
		 */
		load: function() {
		},

		//--------------------------------------------------------------------//
		// Initializing
		//--------------------------------------------------------------------//

		/**
		 * Remove wpforms_form_id from URL.
		 *
		 * @since 1.5.2
		 */
		clearUrlQuery: function() {
			var loc   = window.location,
				query = loc.search;

			if ( query.indexOf( 'wpforms_form_id=' ) !== -1 ) {
				query = query.replace( /([&?]wpforms_form_id=[0-9]*$|wpforms_form_id=[0-9]*&|[?&]wpforms_form_id=[0-9]*(?=#))/, '' );
				history.replaceState( {}, null, loc.origin + loc.pathname + query );
			}
		},

		/**
		 * Load jQuery Validation.
		 *
		 * @since 1.2.3
		 */
		loadValidation: function() {

			// Only load if jQuery validation library exists.
			if ( typeof $.fn.validate !== 'undefined' ) {

				// jQuery Validation library will not correctly validate
				// fields that do not have a name attribute, so we use the
				// `wpforms-input-temp-name` class to add a temporary name
				// attribute before validation is initialized, then remove it
				// before the form submits.
				$( '.wpforms-input-temp-name' ).each( function( index, el ) {
					var random = Math.floor( Math.random() * 9999 ) + 1;
					$( this ).attr( 'name', 'wpf-temp-' + random );
				} );

				// Prepend URL field contents with https:// if user input doesn't contain a schema.
				$( document ).on( 'change', '.wpforms-validate input[type=url]', function() {
					var url = $( this ).val();
					if ( ! url ) {
						return false;
					}
					if ( url.substr( 0, 7 ) !== 'http://' && url.substr( 0, 8 ) !== 'https://' ) {
						$( this ).val( 'https://' + url );
					}
				} );

				$.validator.messages.required = wpforms_settings.val_required;
				$.validator.messages.url      = wpforms_settings.val_url;
				$.validator.messages.email    = wpforms_settings.val_email;
				$.validator.messages.number   = wpforms_settings.val_number;

				// Payments: Validate method for Credit Card Number.
				if ( typeof $.fn.payment !== 'undefined' ) {
					$.validator.addMethod( 'creditcard', function( value, element ) {

						//var type  = $.payment.cardType(value);
						var valid = $.payment.validateCardNumber( value );
						return this.optional( element ) || valid;
					}, wpforms_settings.val_creditcard );

					// @todo validate CVC and expiration
				}

				// Validate method for file extensions.
				$.validator.addMethod( 'extension', function( value, element, param ) {
					param = 'string' === typeof param ? param.replace( /,/g, '|' ) : 'png|jpe?g|gif';
					return this.optional( element ) || value.match( new RegExp( '\\.(' + param + ')$', 'i' ) );
				}, wpforms_settings.val_fileextension );

				// Validate method for file size.
				$.validator.addMethod( 'maxsize', function( value, element, param ) {
					var maxSize = param,
						optionalValue = this.optional( element ),
						i, len, file;
					if ( optionalValue ) {
						return optionalValue;
					}
					if ( element.files && element.files.length ) {
						i = 0;
						len = element.files.length;
						for ( ; i < len; i++ ) {
							file = element.files[i];
							if ( file.size > maxSize ) {
								return false;
							}
						}
					}
					return true;
				}, wpforms_settings.val_filesize );

				$.validator.addMethod( 'step', function( value, element, param ) {

					const decimalPlaces = function( num ) {

						if ( Math.floor( num ) === num ) {
							return 0;
						}

						return num.toString().split( '.' )[1].length || 0;
					};
					const decimals = decimalPlaces( param );
					const decimalToInt = function( num ) {

						return Math.round( num * Math.pow( 10, decimals ) );
					};
					const min = decimalToInt( $( element ).attr( 'min' ) );

					value = decimalToInt( value ) - min;

					return this.optional( element ) || decimalToInt( value ) % decimalToInt( param ) === 0;
				} );

				// Validate email addresses.
				$.validator.methods.email = function( value, element ) {

					// For comments, see wpforms_is_email() function.
					const isEmail = function( value ) {
						if ( value.length > 254 ) {
							return false;
						}

						const valueArr = value.split( '@' );

						if ( valueArr.length !== 2 ) {
							return false;
						}

						const local  = valueArr[ 0 ];
						const domain = valueArr[ 1 ];

						if ( local.length > 63 ) {
							return false;
						}

						const domainArr = domain.split( '.' );

						for ( const domainLabel of domainArr ) {
							if ( domainLabel.length > 63 ) {
								return false;
							}
						}

						return true;
					};

					const isEmailTest = isEmail( value );

					// Test email on the multiple @ and spaces:
					// - no spaces allowed in the local and domain parts
					// - only one @ after the local part allowed
					var structureTest = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( value );

					// Test emails on the multiple dots:
					// - start and finish with dot not allowed
					// - two dots in a row not allowed
					var dotsTest = /^(?!\.)(?!.*?\.\.).*[^.]$/.test( value );

					return this.optional( element ) || ( structureTest && dotsTest && isEmailTest );
				};

				// Validate email by allowlist/blocklist.
				$.validator.addMethod( 'restricted-email', function( value, element ) {

					var validator = this,
						$el = $( element ),
						$field = $el.closest( '.wpforms-field' ),
						$form = $el.closest( '.wpforms-form' ),
						isValid = 'pending';

					if ( ! $el.val().length ) {
						return true;
					}

					this.startRequest( element );
					$.post( {
						url: wpforms_settings.ajaxurl,
						type: 'post',
						async: false,
						data: {
							'action': 'wpforms_restricted_email',
							'form_id': $form.data( 'formid' ),
							'field_id': $field.data( 'field-id' ),
							'email': $el.val(),
						},
						dataType: 'json',
						success: function( response ) {

							var errors = {};

							isValid = response.success && response.data;

							if ( isValid ) {
								validator.toHide = validator.errorsFor( element );
								validator.showErrors();
							} else {
								errors[ element.name ] = wpforms_settings.val_email_restricted;
								validator.showErrors( errors );
							}
							validator.stopRequest( element, isValid );
						},
					} );
					return isValid;
				}, wpforms_settings.val_email_restricted );

				// Validate confirmations.
				$.validator.addMethod( 'confirm', function( value, element, param ) {
					const field = $( element ).closest( '.wpforms-field' );
					return $( field.find( 'input' )[ 0 ] ).val() === $( field.find( 'input' )[ 1 ] ).val();
				}, wpforms_settings.val_confirm );

				// Validate required payments.
				$.validator.addMethod( 'required-payment', function( value, element ) {
					return app.amountSanitize( value ) > 0;
				}, wpforms_settings.val_requiredpayment );

				// Validate 12-hour time.
				$.validator.addMethod( 'time12h', function( value, element ) {
					return this.optional( element ) || /^((0?[1-9]|1[012])(:[0-5]\d){1,2}(\ ?[AP]M))$/i.test( value );
				}, wpforms_settings.val_time12h );

				// Validate 24-hour time.
				$.validator.addMethod( 'time24h', function( value, element ) {
					return this.optional( element ) || /^(([0-1]?[0-9])|([2][0-3])):([0-5]?[0-9])(\ ?[AP]M)?$/i.test( value );
				}, wpforms_settings.val_time24h );

				// Validate Turnstile captcha.
				$.validator.addMethod( 'turnstile', function( value ) {
					return value;
				}, wpforms_settings.val_turnstile_fail_msg );

				// Validate time limits.
				$.validator.addMethod( 'time-limit', function( value, element ) { // eslint-disable-line complexity

					var $input = $( element ),
						minTime = $input.data( 'min-time' ),
						maxTime = $input.data( 'max-time' ),
						isRequired = $input.prop( 'required' ),
						isLimited = typeof minTime !== 'undefined';

					if ( ! isLimited ) {
						return true;
					}

					if ( ! isRequired && app.empty( value ) ) {
						return true;
					}

					if ( app.compareTimesGreaterThan( maxTime, minTime ) ) {
						return app.compareTimesGreaterThan( value, minTime ) && app.compareTimesGreaterThan( maxTime, value );
					}

					return ( app.compareTimesGreaterThan( value, minTime ) && app.compareTimesGreaterThan( value, maxTime ) ) ||
						( app.compareTimesGreaterThan( minTime, value ) && app.compareTimesGreaterThan( maxTime, value  ) );

				}, function( params, element ) {

					var $input = $( element ),
						minTime = $input.data( 'min-time' ),
						maxTime = $input.data( 'max-time' );

					// Replace `00:**pm` with `12:**pm`.
					minTime = minTime.replace( /^00:([0-9]{2})pm$/, '12:$1pm' );
					maxTime = maxTime.replace( /^00:([0-9]{2})pm$/, '12:$1pm' );

					// Properly format time: add space before AM/PM, make uppercase.
					minTime = minTime.replace( /(am|pm)/g, ' $1' ).toUpperCase();
					maxTime = maxTime.replace( /(am|pm)/g, ' $1' ).toUpperCase();

					return wpforms_settings.val_time_limit
						.replace( '{minTime}', minTime )
						.replace( '{maxTime}', maxTime );
				} );

				// Validate checkbox choice limit.
				$.validator.addMethod( 'check-limit', function( value, element ) {
					var $ul = $( element ).closest( 'ul' ),
						$checked = $ul.find( 'input[type="checkbox"]:checked' ),
						choiceLimit = parseInt( $ul.attr( 'data-choice-limit' ) || 0, 10 );

					if ( 0 === choiceLimit ) {
						return true;
					}
					return $checked.length <= choiceLimit;
				}, function( params, element ) {
					var	choiceLimit = parseInt( $( element ).closest( 'ul' ).attr( 'data-choice-limit' ) || 0, 10 );
					return wpforms_settings.val_checklimit.replace( '{#}', choiceLimit );
				} );

				// Validate Smart Phone Field.
				if ( typeof $.fn.intlTelInput !== 'undefined' ) {
					$.validator.addMethod( 'smart-phone-field', function( value, element ) {
						if ( value.match( /[^\d()\-+\s]/ ) ) {
							return false;
						}
						return this.optional( element ) || $( element ).intlTelInput( 'isValidNumber' );
					}, wpforms_settings.val_phone );
				}

				// Validate Inputmask completeness.
				$.validator.addMethod( 'inputmask-incomplete', function( value, element ) {
					if ( value.length === 0 || typeof $.fn.inputmask === 'undefined' ) {
						return true;
					}
					return $( element ).inputmask( 'isComplete' );
				}, wpforms_settings.val_inputmask_incomplete );

				// Validate Payment item value on zero.
				$.validator.addMethod( 'required-positive-number', function( value, element ) {

					return app.amountSanitize( value ) > 0;
				}, wpforms_settings.val_number_positive );

				// Validate US Phone Field.
				$.validator.addMethod( 'us-phone-field', function( value, element ) {
					if ( value.match( /[^\d()\-+\s]/ ) ) {
						return false;
					}
					return this.optional( element ) || value.replace( /[^\d]/g, '' ).length === 10;
				}, wpforms_settings.val_phone );

				// Validate International Phone Field.
				$.validator.addMethod( 'int-phone-field', function( value, element ) {
					if ( value.match( /[^\d()\-+\s]/ ) ) {
						return false;
					}
					return this.optional( element ) || value.replace( /[^\d]/g, '' ).length > 0;
				}, wpforms_settings.val_phone );

				// Validate password strength.
				$.validator.addMethod( 'password-strength', function( value, element ) {

					var $el = $( element );

					return $el.val().trim() === '' && ! $el.hasClass( 'wpforms-field-required' ) || // Don't check the password strength for empty fields which is set as not required.
						WPFormsPasswordField.passwordStrength( value, element ) >= Number( $el.data( 'password-strength-level' ) );
				}, wpforms_settings.val_password_strength );

				// Finally load jQuery Validation library for our forms.
				$( '.wpforms-validate' ).each( function() {

					var form   = $( this ),
						formID = form.data( 'formid' ),
						properties;

					// TODO: cleanup this BC with wpforms_validate.
					if ( typeof window['wpforms_' + formID] !== 'undefined' && window['wpforms_' + formID].hasOwnProperty( 'validate' ) ) {
						properties = window['wpforms_' + formID].validate;
					} else if ( typeof wpforms_validate !== 'undefined' ) {
						properties = wpforms_validate;
					} else {
						properties = {
							errorElement: app.isModernMarkupEnabled() ? 'em' : 'label',
							errorClass: 'wpforms-error',
							validClass: 'wpforms-valid',
							ignore: ':hidden:not(textarea.wp-editor-area), .wpforms-conditional-hide textarea.wp-editor-area',
							errorPlacement: function( error, element ) {

								if ( app.isLikertScaleField( element ) ) {
									element.closest( 'table' ).hasClass( 'single-row' ) ?
										element.closest( '.wpforms-field' ).append( error ) :
										element.closest( 'tr' ).find( 'th' ).append( error );
								} else if ( app.isWrappedField( element ) ) {
									element.closest( '.wpforms-field' ).append( error );
								} else if ( app.isDateTimeField( element ) ) {
									app.dateTimeErrorPlacement( element, error );
								} else if ( app.isFieldInColumn( element ) ) {
									element.parent().append( error );
								} else if ( app.isFieldHasHint( element ) ) {
									element.parent().append( error );
								} else if ( app.isLeadFormsSelect( element ) ) {
									element.parent().parent().append( error );
								} else {
									error.insertAfter( element );
								}

								if ( app.isModernMarkupEnabled() ) {
									error.attr( {
										'role': 'alert',
										'aria-label': wpforms_settings.errorMessagePrefix,
										'for': '',
									} );
								}
							},
							highlight: function( element, errorClass, validClass ) {

								var $element  = $( element ),
									$field    = $element.closest( '.wpforms-field' ),
									inputName = $element.attr( 'name' );

								if ( 'radio' === $element.attr( 'type' ) || 'checkbox' === $element.attr( 'type' ) ) {
									$field.find( 'input[name="' + inputName + '"]' ).addClass( errorClass ).removeClass( validClass );
								} else {
									$element.addClass( errorClass ).removeClass( validClass );
								}

								// Remove password strength container for empty required password field.
								if (
									$element.attr( 'type' ) === 'password' &&
									$element.val().trim() === '' &&
									window.WPFormsPasswordField &&
									$element.data( 'rule-password-strength' ) &&
									$element.hasClass( 'wpforms-field-required' )
								) {
									WPFormsPasswordField.passwordStrength( '', element );
								}

								$field.addClass( 'wpforms-has-error' );
							},
							unhighlight: function( element, errorClass, validClass ) {

								var $element  = $( element ),
									$field    = $element.closest( '.wpforms-field' ),
									inputName = $element.attr( 'name' );

								if ( 'radio' === $element.attr( 'type' ) || 'checkbox' === $element.attr( 'type' ) ) {
									$field.find( 'input[name="' + inputName + '"]' ).addClass( validClass ).removeClass( errorClass );
								} else {
									$element.addClass( validClass ).removeClass( errorClass );
								}

								$field.removeClass( 'wpforms-has-error' );

								// Remove error message to be sure the next time the `errorPlacement` method will be executed.
								if ( app.isModernMarkupEnabled() ) {
									$element.parent().find( 'em.wpforms-error' ).remove();
								}
							},
							submitHandler: function( form ) {

								/**
								 * Submit handler routine.
								 *
								 * @since 1.7.2
								 *
								 * @returns {boolean|void} False if form won't submit.
								 */
								var submitHandlerRoutine = function() {

									var $form = $( form ),
										$submit = $form.find( '.wpforms-submit' ),
										altText = $submit.data( 'alt-text' ),
										recaptchaID = $submit.get( 0 ).recaptchaID;

									if ( $form.data( 'token' ) && 0 === $( '.wpforms-token', $form ).length ) {
										$( '<input type="hidden" class="wpforms-token" name="wpforms[token]" />' )
											.val( $form.data( 'token' ) )
											.appendTo( $form );
									}

									$form.find( '#wpforms-field_recaptcha-error' ).remove();
									$submit.prop( 'disabled', true );

									WPFormsUtils.triggerEvent( $form, 'wpformsFormSubmitButtonDisable', [ $form, $submit ] );

									// Display processing text.
									if ( altText ) {
										$submit.text( altText );
									}

									if ( ! app.empty( recaptchaID ) || recaptchaID === 0 ) {

										// Form contains invisible reCAPTCHA.
										grecaptcha.execute( recaptchaID ).then( null, function( reason ) {

											let errorTag = 'label',
												errorRole = '';

											if ( app.isModernMarkupEnabled() ) {
												errorTag = 'em';
												errorRole = 'role="alert"';
											}

											reason = ( null === reason ) ? '' : '<br>' + reason;
											const error = `<${errorTag} id="wpforms-field_recaptcha-error" class="wpforms-error" ${errorRole}> ${wpforms_settings.val_recaptcha_fail_msg}${reason}</${errorTag}>`;

											$form.find( '.wpforms-recaptcha-container' ).append( error );
											$submit.prop( 'disabled', false );
										} );
										return false;
									}

									// Remove name attributes if needed.
									$( '.wpforms-input-temp-name' ).removeAttr( 'name' );

									app.formSubmit( $form );
								};

								// In the case of active Google reCAPTCHA v3, first, we should call `grecaptcha.execute`.
								// This is needed to obtain proper grecaptcha token before submitting the form.
								if ( typeof wpformsRecaptchaV3Execute === 'function' ) {
									return wpformsRecaptchaV3Execute( submitHandlerRoutine );
								}

								return submitHandlerRoutine();
							},
							invalidHandler: function( event, validator ) {

								if ( typeof validator.errorList[0] !== 'undefined' ) {
									app.scrollToError( $( validator.errorList[0].element ) );
								}
							},
							onkeyup: WPFormsUtils.debounce( // eslint-disable-next-line complexity
								function( element, event ) {

									// This code is copied from JQuery Validate 'onkeyup' method with only one change: 'wpforms-novalidate-onkeyup' class check.
									const excludedKeys = [ 16, 17, 18, 20, 35, 36, 37, 38, 39, 40, 45, 144, 225 ];

									if ( $( element ).hasClass( 'wpforms-novalidate-onkeyup' ) ) {
										return; // Disable onkeyup validation for some elements (e.g. remote calls).
									}

									if ( event.which === 9 && this.elementValue( element ) === '' || $.inArray( event.keyCode, excludedKeys ) !== -1 ) {
										return;
									} else if ( element.name in this.submitted || element.name in this.invalid ) {
										this.element( element );
									}
								},
								1000
							),
							onfocusout: function( element ) {

								// This code is copied from JQuery Validate 'onfocusout' method with only one change: 'wpforms-novalidate-onkeyup' class check.
								var validate = false;

								if ( $( element ).hasClass( 'wpforms-novalidate-onkeyup' ) && ! element.value ) {
									validate = true; // Empty value error handling for elements with onkeyup validation disabled.
								}

								if ( ! this.checkable( element ) && ( element.name in this.submitted || ! this.optional( element ) ) ) {
									validate = true;
								}

								if ( validate ) {
									this.element( element );
								}
							},
							onclick: function( element ) {
								var validate = false,
									type = ( element || {} ).type,
									$el = $( element );

								if ( [ 'checkbox', 'radio' ].indexOf( type ) > -1 ) {
									if ( $el.hasClass( 'wpforms-likert-scale-option' ) ) {
										$el = $el.closest( 'tr' );
									} else {
										$el = $el.closest( '.wpforms-field' );
									}
									$el.find( 'label.wpforms-error, em.wpforms-error' ).remove();
									validate = true;
								}

								if ( validate ) {
									this.element( element );
								}
							},
						};
					}
					form.validate( properties );
				} );
			}
		},

		/**
		 * Is field inside column.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isFieldInColumn: function( element ) {

			return element.parent().hasClass( 'wpforms-one-half' ) ||
				element.parent().hasClass( 'wpforms-two-fifths' ) ||
				element.parent().hasClass( 'wpforms-one-fifth' );
		},

		/**
		 * Is field has hint (sublabel, description, limit text hint, etc.).
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isFieldHasHint: function( element ) {

			return element
				.nextAll( '.wpforms-field-sublabel, .wpforms-field-description, .wpforms-field-limit-text, .wpforms-pass-strength-result' )
				.length > 0;
		},

		/**
		 * Is datetime field.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isDateTimeField: function( element ) {

			return element.hasClass( 'wpforms-timepicker' ) ||
				element.hasClass( 'wpforms-datepicker' ) ||
				( element.is( 'select' ) && element.attr( 'class' ).match( /date-month|date-day|date-year/ ) );
		},

		/**
		 * Is field wrapped in some container.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isWrappedField: function( element ) { // eslint-disable-line complexity

			return 'checkbox' === element.attr( 'type' ) ||
			'radio' === element.attr( 'type' ) ||
			'range' === element.attr( 'type' ) ||
			'select' === element.is( 'select' ) ||
			1 === element.data( 'is-wrapped-field' ) ||
			element.parent().hasClass( 'iti' ) ||
			element.hasClass( 'wpforms-validation-group-member' ) ||
			element.hasClass( 'choicesjs-select' ) ||
			element.hasClass( 'wpforms-net-promoter-score-option' );
		},

		/**
		 * Is likert scale field.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isLikertScaleField: function( element ) {

			return element.hasClass( 'wpforms-likert-scale-option' );
		},

		/**
		 * Is Lead Forms select field.
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} element current form element.
		 *
		 * @returns {boolean} true/false.
		 */
		isLeadFormsSelect: function( element ) {

			return element.parent().hasClass( 'wpforms-lead-forms-select' );
		},

		/**
		 * Print error message into date time fields.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} element current form element.
		 * @param {string} error Error message.
		 */
		dateTimeErrorPlacement: function( element, error ) {

			var $wrapper = element.closest( '.wpforms-field-row-block, .wpforms-field-date-time' );
			if ( $wrapper.length ) {
				if ( ! $wrapper.find( 'label.wpforms-error, em.wpforms-error' ).length ) {
					$wrapper.append( error );
				}
			} else {
				element.closest( '.wpforms-field' ).append( error );
			}
		},

		/**
		 * Load jQuery Date Picker.
		 *
		 * @since 1.2.3
		 */
		loadDatePicker: function() {

			// Only load if jQuery datepicker library exists.
			if ( typeof $.fn.flatpickr !== 'undefined' ) {
				$( '.wpforms-datepicker-wrap' ).each( function() {

					var element = $( this ),
						$input  = element.find( 'input' ),
						form    = element.closest( '.wpforms-form' ),
						formID  = form.data( 'formid' ),
						fieldID = element.closest( '.wpforms-field' ).data( 'field-id' ),
						properties;

					if ( typeof window['wpforms_' + formID + '_' + fieldID] !== 'undefined' && window['wpforms_' + formID + '_' + fieldID].hasOwnProperty( 'datepicker' ) ) {
						properties = window['wpforms_' + formID + '_' + fieldID].datepicker;
					} else if ( typeof window['wpforms_' + formID] !== 'undefined' && window['wpforms_' + formID].hasOwnProperty( 'datepicker' ) ) {
						properties = window['wpforms_' + formID].datepicker;
					} else if ( typeof wpforms_datepicker !== 'undefined' ) {
						properties = wpforms_datepicker;
					} else {
						properties = {
							disableMobile: true,
						};
					}

					// Redefine locale only if user doesn't do that manually, and we have the locale.
					if (
						! properties.hasOwnProperty( 'locale' ) &&
						typeof wpforms_settings !== 'undefined' &&
						wpforms_settings.hasOwnProperty( 'locale' )
					) {
						properties.locale = wpforms_settings.locale;
					}

					properties.wrap = true;
					properties.dateFormat = $input.data( 'date-format' );
					if ( $input.data( 'disable-past-dates' ) === 1 ) {
						properties.minDate = 'today';
					}

					var limitDays = $input.data( 'limit-days' ),
						weekDays = [ 'sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat' ];

					if ( limitDays && limitDays !== '' ) {
						limitDays = limitDays.split( ',' );

						properties.disable = [ function( date ) {

							var limitDay;
							for ( var i in limitDays ) {
								limitDay = weekDays.indexOf( limitDays[ i ] );
								if ( limitDay === date.getDay() ) {
									return false;
								}
							}

							return true;
						} ];
					}

					// Toggle clear date icon.
					properties.onChange = function( selectedDates, dateStr, instance ) {

						var display = dateStr === '' ? 'none' : 'block';
						element.find( '.wpforms-datepicker-clear' ).css( 'display', display );
					};

					element.flatpickr( properties );
				} );
			}
		},

		/**
		 * Load jQuery Time Picker.
		 *
		 * @since 1.2.3
		 */
		loadTimePicker: function() {

			// Only load if jQuery timepicker library exists.
			if ( typeof $.fn.timepicker !== 'undefined' ) {
				$( '.wpforms-timepicker' ).each( function() {
					var element = $( this ),
						form    = element.closest( '.wpforms-form' ),
						formID  = form.data( 'formid' ),
						fieldID = element.closest( '.wpforms-field' ).data( 'field-id' ),
						properties;

					if (
						typeof window['wpforms_' + formID + '_' + fieldID] !== 'undefined' &&
						window['wpforms_' + formID + '_' + fieldID].hasOwnProperty( 'timepicker' )
					) {
						properties = window['wpforms_' + formID + '_' + fieldID].timepicker;
					} else if (
						typeof window['wpforms_' + formID] !== 'undefined' &&
						window['wpforms_' + formID].hasOwnProperty( 'timepicker' )
					) {
						properties = window['wpforms_' + formID].timepicker;
					} else if ( typeof wpforms_timepicker !== 'undefined' ) {
						properties = wpforms_timepicker;
					} else {
						properties = {
							scrollDefault: 'now',
							forceRoundTime: true,
						};
					}

					element.timepicker( properties );
				} );
			}
		},

		/**
		 * Load jQuery input masks.
		 *
		 * @since 1.2.3
		 */
		loadInputMask: function() {

			// Only load if jQuery input mask library exists.
			if ( typeof $.fn.inputmask === 'undefined' ) {
				return;
			}

			// This setting has no effect when switching to the "RTL" mode.
			$( '.wpforms-masked-input' ).inputmask( { rightAlign: false } );
		},

		/**
		 * Load Smart Phone field.
		 *
		 * @since 1.5.2
		 */
		loadSmartPhoneField: function() {

			// Only load if library exists.
			if ( typeof $.fn.intlTelInput === 'undefined' ) {
				return;
			}

			var inputOptions = {};

			// Determine the country by IP if no GDPR restrictions enabled.
			if ( ! wpforms_settings.gdpr ) {
				inputOptions.geoIpLookup = app.currentIpToCountry;
			}

			// Try to kick in an alternative solution if GDPR restrictions are enabled.
			if ( wpforms_settings.gdpr ) {
				var lang = this.getFirstBrowserLanguage(),
					countryCode = lang.indexOf( '-' ) > -1 ? lang.split( '-' ).pop() : '';
			}

			// Make sure the library recognizes browser country code to avoid console error.
			if ( countryCode ) {
				var countryData = window.intlTelInputGlobals.getCountryData();

				countryData = countryData.filter( function( country ) {
					return country.iso2 === countryCode.toLowerCase();
				} );
				countryCode = countryData.length ? countryCode : '';
			}

			// Set default country.
			inputOptions.initialCountry = wpforms_settings.gdpr && countryCode ? countryCode : 'auto';

			$( '.wpforms-smart-phone-field' ).each( function( i, el ) {

				var $el = $( el );

				// Hidden input allows to include country code into submitted data.
				inputOptions.hiddenInput = $el.closest( '.wpforms-field-phone' ).data( 'field-id' );
				inputOptions.utilsScript = wpforms_settings.wpforms_plugin_url + 'assets/pro/lib/intl-tel-input/jquery.intl-tel-input-utils.min.js';

				$el.intlTelInput( inputOptions );

				// For proper validation, we should preserve the name attribute of the input field.
				// But we need to modify original input name not to interfere with a hidden input.
				$el.attr( 'name', 'wpf-temp-' + $el.attr( 'name' ) );

				// Add special class to remove name attribute before submitting.
				// So, only the hidden input value will be submitted.
				$el.addClass( 'wpforms-input-temp-name' );

				// Instantly update a hidden form input with a correct data.
				// Previously "blur" only was used, which is broken in case Enter was used to submit the form.
				$el.on( 'blur input', function() {
					if ( $el.intlTelInput( 'isValidNumber' ) || ! app.empty( window.WPFormsEditEntry ) ) {
						$el.siblings( 'input[type="hidden"]' ).val( $el.intlTelInput( 'getNumber' ) );
					}
				} );
			} );

			// Update hidden input of the `Smart` phone field to be sure the latest value will be submitted.
			$( '.wpforms-form' ).on( 'wpformsBeforeFormSubmit', function() {

				$( this ).find( '.wpforms-smart-phone-field' ).trigger( 'input' );
			} );
		},

		/**
		 * Payments: Do various payment-related tasks on load.
		 *
		 * @since 1.2.6
		 */
		loadPayments: function() {

			// Update Total field(s) with the latest calculation.
			$( '.wpforms-payment-total' ).each( function( index, el ) {
				app.amountTotal( this );
			} );

			// Credit card validation.
			if ( typeof $.fn.payment !== 'undefined' ) {
				$( '.wpforms-field-credit-card-cardnumber' ).payment( 'formatCardNumber' );
				$( '.wpforms-field-credit-card-cardcvc' ).payment( 'formatCardCVC' );
			}
		},

		/**
		 * Load mailcheck.
		 *
		 * @since 1.5.3
		 */
		loadMailcheck: function() {

			// Skip loading if `wpforms_mailcheck_enabled` filter return false.
			if ( ! wpforms_settings.mailcheck_enabled ) {
				return;
			}

			// Only load if library exists.
			if ( typeof $.fn.mailcheck === 'undefined' ) {
				return;
			}

			if ( wpforms_settings.mailcheck_domains.length > 0 ) {
				Mailcheck.defaultDomains = Mailcheck.defaultDomains.concat( wpforms_settings.mailcheck_domains );
			}
			if ( wpforms_settings.mailcheck_toplevel_domains.length > 0 ) {
				Mailcheck.defaultTopLevelDomains = Mailcheck.defaultTopLevelDomains.concat( wpforms_settings.mailcheck_toplevel_domains );
			}

			// Mailcheck suggestion.
			$( document ).on( 'blur', '.wpforms-field-email input', function() {

				var $input = $( this ),
					id = $input.attr( 'id' );

				$input.mailcheck( {
					suggested: function( $el, suggestion ) {

						if ( suggestion.address.match( /^xn--/ ) ) {
							suggestion.full = punycode.toUnicode( decodeURI( suggestion.full ) );

							var parts = suggestion.full.split( '@' );

							suggestion.address = parts[0];
							suggestion.domain = parts[1];
						}

						if ( suggestion.domain.match( /^xn--/ ) ) {
							suggestion.domain = punycode.toUnicode( decodeURI( suggestion.domain ) );
						}

						var address = decodeURI( suggestion.address ).replaceAll( /[<>'"()/\\|:;=@%&\s]/ig, '' ).substr( 0, 64 ),
							domain = decodeURI( suggestion.domain ).replaceAll( /[<>'"()/\\|:;=@%&+_\s]/ig, '' );

						suggestion = '<a href="#" class="mailcheck-suggestion" data-id="' + id + '" title="' + wpforms_settings.val_email_suggestion_title + '">' + address + '@' + domain + '</a>';
						suggestion = wpforms_settings.val_email_suggestion.replace( '{suggestion}', suggestion );

						$el.closest( '.wpforms-field' ).find( '#' + id + '_suggestion' ).remove();
						$el.parent().append( '<label class="wpforms-error mailcheck-error" id="' + id + '_suggestion">' + suggestion + '</label>' );
					},
					empty: function() {

						$( '#' + id + '_suggestion' ).remove();
					},
				} );
			} );

			// Apply Mailcheck suggestion.
			$( document ).on( 'click', '.wpforms-field-email .mailcheck-suggestion', function( e ) {

				var $suggestion = $( this ),
					$field = $suggestion.closest( '.wpforms-field' ),
					id = $suggestion.data( 'id' );

				e.preventDefault();
				$field.find( '#' + id ).val( $suggestion.text() );
				$suggestion.parent().remove();
			} );

		},

		/**
		 * Load Choices.js library for all Modern style Dropdown fields (<select>).
		 *
		 * @since 1.6.1
		 */
		loadChoicesJS: function() {

			// Loads if function exists.
			if ( typeof window.Choices !== 'function' ) {
				return;
			}

			$( '.wpforms-field-select-style-modern .choicesjs-select, .wpforms-field-payment-select .choicesjs-select' ).each( function( idx, el ) {

				if ( $( el ).data( 'choicesjs' ) ) {
					return;
				}

				var args          = window.wpforms_choicesjs_config || {},
					searchEnabled = $( el ).data( 'search-enabled' );

				args.searchEnabled  = 'undefined' !== typeof searchEnabled ? searchEnabled : true;
				args.callbackOnInit = function() {

					var self      = this,
						$element  = $( self.passedElement.element ),
						$input    = $( self.input.element ),
						sizeClass = $element.data( 'size-class' );

					// Remove hidden attribute and hide `<select>` like a screen-reader text.
					// It's important for field validation.
					$element
						.removeAttr( 'hidden' )
						.addClass( self.config.classNames.input + '--hidden' );

					// Add CSS-class for size.
					if ( sizeClass ) {
						$( self.containerOuter.element ).addClass( sizeClass );
					}

					/**
					 * If a multiple select has selected choices - hide a placeholder text.
					 * In case if select is empty - we return placeholder text back.
					 */
					if ( $element.prop( 'multiple' ) ) {

						// On init event.
						$input.data( 'placeholder', $input.attr( 'placeholder' ) );

						if ( self.getValue( true ).length ) {
							$input.removeAttr( 'placeholder' );
						}
					}

					// On change event.
					$element.on( 'change', function() {

						var validator;

						// Listen if multiple select has choices.
						if ( $element.prop( 'multiple' ) ) {
							self.getValue( true ).length ?
								$input.removeAttr( 'placeholder' ) :
								$input.attr( 'placeholder', $input.data( 'placeholder' ) );
						}

						validator = $element.closest( 'form' ).data( 'validator' );

						if ( ! validator ) {
							return;
						}

						validator.element( $element );
					} );
				};

				args.callbackOnCreateTemplates = function() {

					var self      = this,
						$element  = $( self.passedElement.element );

					return {

						// Change default template for option.
						option: function( item ) {

							var opt = Choices.defaults.templates.option.call( this, item );

							// Add a `.placeholder` class for placeholder option - it needs for WPForm CL.
							if ( 'undefined' !== typeof item.placeholder && true === item.placeholder ) {
								opt.classList.add( 'placeholder' );
							}

							// Add a `data-amount` attribute for payment dropdown.
							// It will be a copy from a Choices.js `data-custom-properties` attribute.
							if ( $element.hasClass( 'wpforms-payment-price' ) && 'undefined' !== typeof item.customProperties && null !== item.customProperties ) {
								opt.dataset.amount = item.customProperties;
							}

							return opt;
						},
					};
				};

				// Save choicesjs instance for future access.
				$( el ).data( 'choicesjs', new Choices( el, args ) );
			} );
		},

		//--------------------------------------------------------------------//
		// Binds.
		//--------------------------------------------------------------------//

		/**
		 * Element bindings.
		 *
		 * @since 1.2.3
		 */
		bindUIActions: function() {

			// Pagebreak navigation.
			$( document ).on( 'click', '.wpforms-page-button', function( event ) {
				event.preventDefault();
				app.pagebreakNav( this );
			} );

			// Payments: Update Total field(s) when latest calculation.
			$( document ).on( 'change input', '.wpforms-payment-price', function() {
				app.amountTotal( this, true );
			} );

			// Payments: Restrict user input payment fields.
			$( document ).on( 'input', '.wpforms-payment-user-input', function() {
				var $this = $( this ),
					amount = $this.val();
				$this.val( amount.replace( /[^0-9.,]/g, '' ) );
			} );

			// Payments: Sanitize/format user input amounts.
			$( document ).on( 'focusout', '.wpforms-payment-user-input', function() {
				var $this  = $( this ),
					amount = $this.val();

				if ( ! amount ) {
					return amount;
				}

				var sanitized = app.amountSanitize( amount ),
					formatted = app.amountFormat( sanitized );

				$this.val( formatted );
			} );

			// Payments: Update Total field(s) when conditionals are processed.
			$( document ).on( 'wpformsProcessConditionals', function( e, el ) {
				app.amountTotal( el, true );
			} );

			// Rating field: hover effect.
			$( document ).on( 'mouseenter', '.wpforms-field-rating-item', function() {
				$( this ).parent().find( '.wpforms-field-rating-item' ).removeClass( 'selected hover' );
				$( this ).prevAll().addBack().addClass( 'hover' );
			} ).on( 'mouseleave', '.wpforms-field-rating-item', function() {
				$( this ).parent().find( '.wpforms-field-rating-item' ).removeClass( 'selected hover' );
				$( this ).parent().find( 'input:checked' ).parent().prevAll().addBack().addClass( 'selected' );
			} );

			// Rating field: toggle selected state.
			$( document ).on( 'change', '.wpforms-field-rating-item input', function() {

				var $this  = $( this ),
					$wrap  = $this.closest( '.wpforms-field-rating-items' ),
					$items = $wrap.find( '.wpforms-field-rating-item' );

				$items.removeClass( 'hover selected' );
				$this.parent().prevAll().addBack().addClass( 'selected' );
			} );

			// Rating field: preselect the selected rating (from dynamic/fallback population).
			$( function() {
				$( '.wpforms-field-rating-item input:checked' ).trigger( 'change' );
			} );

			// Checkbox/Radio/Payment checkbox: make labels keyboard-accessible.
			$( document ).on( 'keydown', '.wpforms-image-choices-item label', function( event ) {

				const $label  = $( this ),
					$field = $label.closest( '.wpforms-field' );

				if ( $field.hasClass( 'wpforms-conditional-hide' ) ) {
					event.preventDefault();
					return false;
				}

				// Cause the input to be clicked when pressing Space bar on the label.
				if ( event.keyCode !== 32 ) {
					return;
				}

				$label.find( 'input' ).trigger( 'click' );
				event.preventDefault();
			} );

			// IE: Click on the `image choice` image should trigger the click event on the input (checkbox or radio) field.
			if ( window.document.documentMode ) {
				$( document ).on( 'click', '.wpforms-image-choices-item img', function() {

					$( this ).closest( 'label' ).find( 'input' ).trigger( 'click' );
				} );
			}

			$( document ).on( 'change', '.wpforms-field-checkbox input, .wpforms-field-radio input, .wpforms-field-payment-multiple input, .wpforms-field-payment-checkbox input, .wpforms-field-gdpr-checkbox input', function( event ) {

				var $this  = $( this ),
					$field = $this.closest( '.wpforms-field' );

				if ( $field.hasClass( 'wpforms-conditional-hide' ) ) {
					event.preventDefault();
					return false;
				}

				switch ( $this.attr( 'type' ) ) {
					case 'radio':
						$this.closest( 'ul' ).find( 'li' ).removeClass( 'wpforms-selected' ).find( 'input[type=radio]' ).removeProp( 'checked' );
						$this
							.prop( 'checked', true )
							.closest( 'li' ).addClass( 'wpforms-selected' );
						break;

					case 'checkbox':
						if ( $this.is( ':checked' ) ) {
							$this.closest( 'li' ).addClass( 'wpforms-selected' );
							$this.prop( 'checked', true );
						} else {
							$this.closest( 'li' ).removeClass( 'wpforms-selected' );
							$this.prop( 'checked', false );
						}
						break;
				}
			} );

			// Upload fields: Check combined file size.
			$( document ).on( 'change', '.wpforms-field-file-upload input[type=file]:not(".dropzone-input")', function() {

				var $this       = $( this ),
					$uploads    = $this.closest( 'form.wpforms-form' ).find( '.wpforms-field-file-upload input:not(".dropzone-input")' ),
					totalSize   = 0,
					postMaxSize = Number( wpforms_settings.post_max_size ),
					errorMsg    = '<div class="wpforms-error-container-post_max_size">' + wpforms_settings.val_post_max_size + '</div>',
					errorCntTpl = '<div class="wpforms-error-container">{errorMsg}</div>',
					$submitCnt  = $this.closest( 'form.wpforms-form' ).find( '.wpforms-submit-container' ),
					$submitBtn  = $submitCnt.find( 'button.wpforms-submit' ),
					$errorCnt   = $submitCnt.prev(),
					$form       = $submitBtn.closest( 'form' );

				// Calculating totalSize.
				$uploads.each( function() {
					var $upload = $( this ),
						i = 0,
						len = $upload[0].files.length;
					for ( ; i < len; i++ ) {
						totalSize += $upload[0].files[i].size;
					}
				} );

				// Checking totalSize.
				if ( totalSize < postMaxSize ) {

					// Remove error and release submit button.
					$errorCnt.find( '.wpforms-error-container-post_max_size' ).remove();
					$submitBtn.prop( 'disabled', false );

					WPFormsUtils.triggerEvent( $form, 'wpformsCombinedUploadsSizeOk', [ $form, $errorCnt ] );

					return;
				}

				// Convert sizes to Mb.
				totalSize = Number( ( totalSize / 1048576 ).toFixed( 3 ) );
				postMaxSize = Number( ( postMaxSize / 1048576 ).toFixed( 3 ) );

				// Preparing error message.
				errorMsg = errorMsg.replace( /{totalSize}/, totalSize ).replace( /{maxSize}/, postMaxSize );

				// Output error message.
				if ( $errorCnt.hasClass( 'wpforms-error-container' ) ) {
					$errorCnt.find( '.wpforms-error-container-post_max_size' ).remove();
					$errorCnt.append( errorMsg );
				} else {
					$submitCnt.before( errorCntTpl.replace( /{errorMsg}/, errorMsg ) );
					$errorCnt = $submitCnt.prev();
				}

				// Disable submit button.
				$submitBtn.prop( 'disabled', true );

				WPFormsUtils.triggerEvent( $form, 'wpformsCombinedUploadsSizeError', [ $form, $errorCnt ] );
			} );

			// Number Slider field: update hints.
			$( document ).on( 'change input', '.wpforms-field-number-slider input[type=range]', function( event ) {
				var hintEl = $( event.target ).siblings( '.wpforms-field-number-slider-hint' );

				hintEl.html( hintEl.data( 'hint' ).replace( '{value}', '<b>' + event.target.value + '</b>' ) );
			} );

			// Enter key event.
			$( document ).on( 'keydown', '.wpforms-form input', function( e ) {

				if ( e.keyCode !== 13 ) {
					return;
				}

				var $t = $( this ),
					$page = $t.closest( '.wpforms-page' );

				if ( $page.length === 0 ) {
					return;
				}

				if ( [ 'text', 'tel', 'number', 'email', 'url', 'radio', 'checkbox' ].indexOf( $t.attr( 'type' ) ) < 0 ) {
					return;
				}

				if ( $t.hasClass( 'wpforms-datepicker' ) ) {
					$t.flatpickr( 'close' );
				}

				e.preventDefault();

				if ( $page.hasClass( 'last' ) ) {
					$page.closest( '.wpforms-form' ).find( '.wpforms-submit' ).trigger( 'click' );
					return;
				}

				$page.find( '.wpforms-page-next' ).trigger( 'click' );
			} );

			// Allow only numbers, minus and decimal point to be entered into the Numbers field.
			$( document ).on( 'keypress', '.wpforms-field-number input', function( e ) {

				return /^[-0-9.]+$/.test( String.fromCharCode( e.keyCode || e.which ) );
			} );
		},

		/**
		 * Entry preview field callback for a page changing.
		 *
		 * @since 1.6.9
		 * @deprecated 1.7.0
		 *
		 * @param {Event}  event       Event.
		 * @param {int}    currentPage Current page.
		 * @param {jQuery} $form       Current form.
		 */
		entryPreviewFieldPageChange: function( event, currentPage, $form ) {

			console.warn( 'WARNING! Obsolete function called. Function wpforms.entryPreviewFieldPageChange has been deprecated, please use the WPFormsEntryPreview.pageChange function instead!' );
			WPFormsEntryPreview.pageChange( event, currentPage, $form );
		},

		/**
		 * Update the entry preview fields on the page.
		 *
		 * @since 1.6.9
		 * @deprecated 1.7.0
		 *
		 * @param {int}    currentPage Current page.
		 * @param {jQuery} $form       Current form.
		 */
		entryPreviewFieldUpdate: function( currentPage, $form ) {

			console.warn( 'WARNING! Obsolete function called. Function wpforms.entryPreviewFieldUpdate has been deprecated, please use the WPFormsEntryPreview.update function instead!' );
			WPFormsEntryPreview.update( currentPage, $form );
		},

		/**
		 * Scroll to and focus on the field with error.
		 *
		 * @since 1.5.8
		 *
		 * @param {jQuery} $el Form, container or input element jQuery object.
		 */
		scrollToError: function( $el ) {

			if ( $el.length === 0 ) {
				return;
			}

			// Look for a field with an error inside an $el.
			var $field = $el.find( '.wpforms-field.wpforms-has-error' );

			// Look outside in not found inside.
			if ( $field.length === 0 ) {
				$field = $el.closest( '.wpforms-field' );
			}

			if ( $field.length === 0 ) {
				return;
			}

			var offset = $field.offset();

			if ( typeof offset === 'undefined' ) {
				return;
			}

			app.animateScrollTop( offset.top - 75, 750 ).done( function() {
				var $error = $field.find( '.wpforms-error' ).first();
				if ( typeof $error.focus === 'function' ) {
					$error.trigger( 'focus' );
				}
			} );
		},

		/**
		 * Update Pagebreak navigation.
		 *
		 * @since 1.2.2
		 *
		 * @param {jQuery} el jQuery element object.
		 */
		pagebreakNav: function( el ) {
			const $this = $( el ),
				action  = $this.data( 'action' ),
				page    = $this.data( 'page' ),
				$form   = $this.closest( '.wpforms-form' ),
				$page   = $form.find( '.wpforms-page-' + page );

			app.saveTinyMCE();

			if ( 'next' === action && ( typeof $.fn.validate !== 'undefined' ) ) {
				app.checkForInvalidFields( $form, $page, function() {
					app.navigateToPage( $this, action, page, $form, $page );
				} );
				return;
			}

			if ( 'prev' === action || 'next' === action ) {
				app.navigateToPage( $this, action, page, $form, $page );
			}
		},

		/**
		 * Check the validity of all the fields in the current page.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery}   $form    WPForms element object.
		 * @param {jQuery}   $page    Current page element object in page break context.
		 * @param {Function} callback Callback to run when all fields are valid.
		 */
		checkForInvalidFields: function( $form, $page, callback ) {
			const validator = $form.data( 'validator' );
			if ( ! validator ) {
				return;
			}

			if ( validator.pendingRequest > 0 ) {
				setTimeout( function() {
					app.checkForInvalidFields( $form, $page, callback );
				}, 800 );

				return;
			}

			let valid = true;

			$page.find( ':input' ).each( function( index, el ) {

				// Skip input fields without `name` attribute, which could have fields.
				// E.g. `Placeholder` input for Modern dropdown.
				if ( ! $( el ).attr( 'name' ) ) {
					return;
				}

				if ( ! $( el ).valid() ) {
					valid = false;
				}
			} );

			if ( ! valid ) {
				app.scrollToError( $page );
			} else {
				callback();
			}
		},

		/**
		 * Navigate through page break pages.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $this  jQuery element of the next / prev nav button.
		 * @param {string} action The navigation action.
		 * @param {int}    page   Current page number.
		 * @param {jQuery} $form  WPForms element object.
		 * @param {jQuery} $page  Current page element object in page break context.
		 */
		navigateToPage: function( $this, action, page, $form, $page ) {

			let nextPage = page;

			if ( 'next' === action ) {
				nextPage += 1;
			} else if ( 'prev' === action ) {
				nextPage -= 1;
			}

			let event = WPFormsUtils.triggerEvent( $this, 'wpformsBeforePageChange', [ nextPage, $form, action ] );

			// Allow callbacks on `wpformsBeforePageChange` to cancel page changing by triggering `event.preventDefault()`.
			if ( event.isDefaultPrevented() ) {
				return;
			}

			$form.find( '.wpforms-page' ).hide();

			let $destinationPage = $form.find( '.wpforms-page-' + nextPage );
			$destinationPage.show();

			app.toggleReCaptchaAndSubmitDisplay( $form, action, $destinationPage );

			const pageScroll = app.getPageScroll( $form );
			if ( pageScroll ) {
				app.animateScrollTop( $form.offset().top - pageScroll, 750, null );
			}

			$this.trigger( 'wpformsPageChange', [ nextPage, $form, action ] );

			app.manipulateIndicator( nextPage, $form );
		},

		/**
		 * Toggle the reCaptcha and submit container display.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $form            WPForms element object.
		 * @param {string} action           The navigation action.
		 * @param {jQuery} $destinationPage Destination Page element object.
		 */
		toggleReCaptchaAndSubmitDisplay: function( $form, action, $destinationPage ) {
			const $submit  = $form.find( '.wpforms-submit-container' ),
				$reCAPTCHA = $form.find( '.wpforms-recaptcha-container' );

			if ( 'next' === action && $destinationPage.hasClass( 'last' ) ) {
				$reCAPTCHA.show();
				$submit.show();
			} else if ( 'prev' === action ) {
				$reCAPTCHA.hide();
				$submit.hide();
			}
		},

		/**
		 * Get the page scroll position.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $form WPForms element object.
		 * @returns {number|boolean} Returns a number if position to page scroll is found.
		 * Otherwise, returns `false` if position isn't found.
		 */
		getPageScroll: function( $form ) {
			if ( false === window.wpforms_pageScroll ) {
				return false;
			}

			if ( ! app.empty( window.wpform_pageScroll ) ) {
				return window.wpform_pageScroll;
			}

			// Page scroll.
			return $form.find( '.wpforms-page-indicator' ).data( 'scroll' ) !== 0 ? 75 : false;
		},

		/**
		 * Manipulate the indicator.
		 *
		 * @since 1.7.6
		 *
		 * @param {int} nextPage The next's / destination's page number.
		 * @param {jQuery} $form WPForms element object.
		 */
		manipulateIndicator: function( nextPage, $form ) {
			const $indicator = $form.find( '.wpforms-page-indicator' );

			if ( ! $indicator ) {
				return;
			}

			const theme = $indicator.data( 'indicator' );

			if ( 'connector' === theme || 'circles' === theme ) {
				app.manipulateConnectorAndCirclesIndicator( $indicator, theme, nextPage );
				return;
			}

			if ( 'progress' === theme ) {
				app.manipulateProgressIndicator( $indicator, $form, nextPage );
			}
		},

		/**
		 * Manipulate 'circles' or 'connector' theme indicator.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $indicator The indicator jQuery element object.
		 * @param {string} theme      Indicator theme.
		 * @param {int}    nextPage   The next's / destination's page number.
		 */
		manipulateConnectorAndCirclesIndicator: function( $indicator, theme, nextPage ) {
			const color = $indicator.data( 'indicator-color' );

			$indicator.find( '.wpforms-page-indicator-page' ).removeClass( 'active' );
			$indicator.find( '.wpforms-page-indicator-page-' + nextPage ).addClass( 'active' );
			$indicator.find( '.wpforms-page-indicator-page-number' ).removeAttr( 'style' );
			$indicator.find( '.active .wpforms-page-indicator-page-number' ).css( 'background-color', color );

			if ( 'connector' === theme ) {
				$indicator.find( '.wpforms-page-indicator-page-triangle' ).removeAttr( 'style' );
				$indicator.find( '.active .wpforms-page-indicator-page-triangle' ).css( 'border-top-color', color );
			}
		},

		/**
		 * Manipulate 'progress' theme indicator.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $indicator The indicator jQuery element object.
		 * @param {jQuery} $form      WPForms element object.
		 * @param {int}    nextPage   The next's / destination's page number.
		 */
		manipulateProgressIndicator: function( $indicator, $form, nextPage ) {
			let $pageTitle = $indicator.find( '.wpforms-page-indicator-page-title' ),
				$pageSep   = $indicator.find( '.wpforms-page-indicator-page-title-sep' ),
				totalPages = $form.find( '.wpforms-page' ).length,
				width      = ( nextPage / totalPages ) * 100;

			$indicator.find( '.wpforms-page-indicator-page-progress' ).css( 'width', width + '%' );
			$indicator.find( '.wpforms-page-indicator-steps-current' ).text( nextPage );

			if ( $pageTitle.data( 'page-' + nextPage + '-title' ) ) {
				$pageTitle.css( 'display', 'inline' ).text( $pageTitle.data( 'page-' + nextPage + '-title' ) );
				$pageSep.css( 'display', 'inline' );
			} else {
				$pageTitle.css( 'display', 'none' );
				$pageSep.css( 'display', 'none' );
			}
		},

		/**
		 * OptinMonster compatibility.
		 *
		 * Re-initialize after OptinMonster loads to accommodate changes that
		 * have occurred to the DOM.
		 *
		 * @since 1.5.0
		 */
		bindOptinMonster: function() {

			// OM v5.
			document.addEventListener( 'om.Campaign.load', function( event ) {
				app.ready();
				app.optinMonsterRecaptchaReset( event.detail.Campaign.data.id );
			} );

			// OM Legacy.
			$( document ).on( 'OptinMonsterOnShow', function( event, data, object ) {
				app.ready();
				app.optinMonsterRecaptchaReset( data.optin );
			} );
		},

		/**
		 * Reset/recreate hCaptcha/reCAPTCHA v2 inside OptinMonster.
		 *
		 * @since 1.5.0
		 * @since 1.6.4 Added hCaptcha support.
		 *
		 * @param {string} optinId OptinMonster ID.
		 */
		optinMonsterRecaptchaReset: function( optinId ) {

			var $form             = $( '#om-' + optinId ).find( '.wpforms-form' ),
				$captchaContainer = $form.find( '.wpforms-recaptcha-container' ),
				$captcha          = $form.find( '.g-recaptcha' );

			if ( $form.length && $captcha.length ) {

				var captchaSiteKey = $captcha.attr( 'data-sitekey' ),
					captchaID      = 'recaptcha-' + Date.now(),
					apiVar         = $captchaContainer.hasClass( 'wpforms-is-hcaptcha' ) ? hcaptcha : grecaptcha;

				$captcha.remove();
				$captchaContainer.prepend( '<div class="g-recaptcha" id="' + captchaID + '" data-sitekey="' + captchaSiteKey + '"></div>' );

				apiVar.render(
					captchaID,
					{
						sitekey: captchaSiteKey,
						callback: function() {
							wpformsRecaptchaCallback( $( '#' + captchaID ) );
						},
					}
				);
			}
		},

		//--------------------------------------------------------------------//
		// Other functions.
		//--------------------------------------------------------------------//

		/**
		 * Payments: Run amount calculation and update the Total field value.
		 *
		 * @since 1.2.3
		 * @since 1.5.1 Added support for payment-checkbox field.
		 *
		 * @param {object} el jQuery DOM object.
		 * @param {boolean} validate Whether to validate or not.
		 */
		amountTotal: function( el, validate ) {

			validate = validate || false;

			var $form    = $( el ).closest( '.wpforms-form' ),
				currency = app.getCurrency(),
				total    = app.amountTotalCalc( $form ),
				totalFormatted,
				totalFormattedSymbol;

			totalFormatted = app.amountFormat( total );

			if ( 'left' === currency.symbol_pos ) {
				totalFormattedSymbol = currency.symbol + ' ' + totalFormatted;
			} else {
				totalFormattedSymbol = totalFormatted + ' ' + currency.symbol;
			}

			$form.find( '.wpforms-payment-total' ).each( function( index, el ) {
				if ( 'hidden' === $( this ).attr( 'type' ) || 'text' === $( this ).attr( 'type' ) ) {
					$( this ).val( totalFormattedSymbol );
					if ( 'text' === $( this ).attr( 'type' ) && validate && $form.data( 'validator' ) ) {
						$( this ).valid();
					}
				} else {
					$( this ).text( totalFormattedSymbol );
				}
			} );
		},

		/**
		 * Payments: Calculate a total amount without formatting.
		 *
		 * @since 1.6.7.1
		 *
		 * @param {jQuery} $form Form element.
		 *
		 * @returns {number} Total amount.
		 */
		amountTotalCalc: function( $form ) {

			var total = 0;

			$( '.wpforms-payment-price', $form ).each( function() {

				var amount = 0,
					$this  = $( this ),
					type   = $this.attr( 'type' );

				if ( $this.closest( '.wpforms-field-payment-single' ).hasClass( 'wpforms-conditional-hide' ) ) {
					return;
				}

				if ( type === 'text' || type === 'hidden' ) {
					amount = $this.val();
				} else if ( ( type === 'radio' || type === 'checkbox' ) && $this.is( ':checked' ) ) {
					amount = $this.data( 'amount' );
				} else if ( $this.is( 'select' ) && $this.find( 'option:selected' ).length > 0 ) {
					amount = $this.find( 'option:selected' ).data( 'amount' );
				}

				if ( ! app.empty( amount ) ) {
					amount = app.amountSanitize( amount );
					total  = Number( total ) + Number( amount );
				}
			} );

			$( document ).trigger( 'wpformsAmountTotalCalculated', [ $form, total ] );

			return total;
		},

		/**
		 * Sanitize amount and convert to standard format for calculations.
		 *
		 * @since 1.2.6
		 *
		 * @param {string} amount Amount to sanitize.
		 *
		 * @returns {string} Sanitized amount.
		 */
		amountSanitize: function( amount ) {

			var currency = app.getCurrency();

			amount = amount.toString().replace( /[^0-9.,]/g, '' );

			if ( currency.decimal_sep === ',' ) {
				if ( currency.thousands_sep === '.' && amount.indexOf( currency.thousands_sep ) !== -1 ) {
					amount = amount.replace( new RegExp( '\\' + currency.thousands_sep, 'g' ), '' );
				} else if ( currency.thousands_sep === '' && amount.indexOf( '.' ) !== -1 ) {
					amount = amount.replace( /\./g, '' );
				}
				amount = amount.replace( currency.decimal_sep, '.' );
			} else if ( currency.thousands_sep === ',' && ( amount.indexOf( currency.thousands_sep ) !== -1 ) ) {
				amount = amount.replace( new RegExp( '\\' + currency.thousands_sep, 'g' ), '' );
			}
			return app.numberFormat( amount, currency.decimals, '.', '' );
		},

		/**
		 * Format amount.
		 *
		 * @since 1.2.6
		 *
		 * @param {string|number} amount Amount to format.
		 *
		 * @returns {string} Formatted amount.
		 */
		amountFormat: function( amount ) {

			var currency = app.getCurrency();

			amount = String( amount );

			// Format the amount
			if ( ',' === currency.decimal_sep && ( amount.indexOf( currency.decimal_sep ) !== -1 ) ) {
				var sepFound = amount.indexOf( currency.decimal_sep ),
					whole    = amount.substr( 0, sepFound ),
					part     = amount.substr( sepFound + 1, amount.length - 1 );
				amount = whole + '.' + part;
			}

			// Strip , from the amount (if set as the thousand separator)
			if ( ',' === currency.thousands_sep && ( amount.indexOf( currency.thousands_sep ) !== -1 ) ) {
				amount = amount.replace( /,/g, '' );
			}

			if ( app.empty( amount ) ) {
				amount = 0;
			}

			return app.numberFormat( amount, currency.decimals, currency.decimal_sep, currency.thousands_sep );
		},

		/**
		 * Get site currency settings.
		 *
		 * @since 1.2.6
		 *
		 * @returns {object} Currency data object.
		 */
		getCurrency: function() {

			var currency = {
				code: 'USD',
				thousands_sep: ',',
				decimals: 2,
				decimal_sep: '.',
				symbol: '$',
				symbol_pos: 'left',
			};

			// Backwards compatibility.
			if ( typeof wpforms_settings.currency_code !== 'undefined' ) {
				currency.code = wpforms_settings.currency_code;
			}
			if ( typeof wpforms_settings.currency_thousands !== 'undefined' ) {
				currency.thousands_sep = wpforms_settings.currency_thousands;
			}
			if ( typeof wpforms_settings.currency_decimals !== 'undefined' ) {
				currency.decimals = wpforms_settings.currency_decimals;
			}
			if ( typeof wpforms_settings.currency_decimal !== 'undefined' ) {
				currency.decimal_sep = wpforms_settings.currency_decimal;
			}
			if ( typeof wpforms_settings.currency_symbol !== 'undefined' ) {
				currency.symbol = wpforms_settings.currency_symbol;
			}
			if ( typeof wpforms_settings.currency_symbol_pos !== 'undefined' ) {
				currency.symbol_pos = wpforms_settings.currency_symbol_pos;
			}

			return currency;
		},

		/**
		 * Format number.
		 *
		 * @see http://locutus.io/php/number_format/
		 *
		 * @since 1.2.6
		 *
		 * @param {string} number       Number to format.
		 * @param {number} decimals     How many decimals should be there.
		 * @param {string} decimalSep   What is the decimal separator.
		 * @param {string} thousandsSep What is the thousand separator.
		 *
		 * @returns {string} Formatted number.
		 */
		numberFormat: function( number, decimals, decimalSep, thousandsSep ) {

			number = ( number + '' ).replace( /[^0-9+\-Ee.]/g, '' );
			var n = ! isFinite( +number ) ? 0 : +number;
			var prec = ! isFinite( +decimals ) ? 0 : Math.abs( decimals );
			var sep = ( 'undefined' === typeof thousandsSep ) ? ',' : thousandsSep;
			var dec = ( 'undefined' === typeof decimalSep ) ? '.' : decimalSep;
			var s;

			var toFixedFix = function( n, prec ) {
				var k = Math.pow( 10, prec );
				return '' + ( Math.round( n * k ) / k ).toFixed( prec );
			};

			// @todo: for IE parseFloat(0.55).toFixed(0) = 0;
			s = ( prec ? toFixedFix( n, prec ) : '' + Math.round( n ) ).split( '.' );
			if ( s[0].length > 3 ) {
				s[0] = s[0].replace( /\B(?=(?:\d{3})+(?!\d))/g, sep );
			}
			if ( ( s[1] || '' ).length < prec ) {
				s[1] = s[1] || '';
				s[1] += new Array( prec - s[1].length + 1 ).join( '0' );
			}

			return s.join( dec );
		},

		/**
		 * Empty check similar to PHP.
		 *
		 * @see http://locutus.io/php/empty/
		 *
		 * @since 1.2.6
		 *
		 * @param {mixed} mixedVar Variable to check.
		 *
		 * @returns {boolean} Whether the var is empty or not.
		 */
		empty: function( mixedVar ) {

			var undef;
			var key;
			var i;
			var len;
			var emptyValues = [ undef, null, false, 0, '', '0' ];

			for ( i = 0, len = emptyValues.length; i < len; i++ ) {
				if ( mixedVar === emptyValues[i] ) {
					return true;
				}
			}

			if ( 'object' === typeof mixedVar ) {
				for ( key in mixedVar ) {
					if ( mixedVar.hasOwnProperty( key ) ) {
						return false;
					}
				}
				return true;
			}

			return false;
		},

		/**
		 * Set cookie container user UUID.
		 *
		 * @since 1.3.3
		 */
		setUserIndentifier: function() {

			if ( ( ( ! window.hasRequiredConsent && typeof wpforms_settings !== 'undefined' && wpforms_settings.uuid_cookie ) || ( window.hasRequiredConsent && window.hasRequiredConsent() ) ) && ! app.getCookie( '_wpfuuid' ) ) {

				// Generate UUID - http://stackoverflow.com/a/873856/1489528
				var s         = new Array( 36 ),
					hexDigits = '0123456789abcdef',
					uuid;

				for ( var i = 0; i < 36; i++ ) {
					s[i] = hexDigits.substr( Math.floor( Math.random() * 0x10 ), 1 );
				}
				s[14] = '4';
				s[19] = hexDigits.substr( ( s[19] & 0x3 ) | 0x8, 1 );
				s[8]  = s[13] = s[18] = s[23] = '-';

				uuid = s.join( '' );

				app.createCookie( '_wpfuuid', uuid, 3999 );
			}
		},

		/**
		 * Create cookie.
		 *
		 * @since 1.3.3
		 *
		 * @param {string} name  Cookie name.
		 * @param {string} value Cookie value.
		 * @param {string} days  Whether it should expire and when.
		 */
		createCookie: function( name, value, days ) {

			var expires = '';
			var secure = '';

			if ( wpforms_settings.is_ssl ) {
				secure = ';secure';
			}

			// If we have a days value, set it in the expiry of the cookie.
			if ( days ) {

				// If -1 is our value, set a session-based cookie instead of a persistent cookie.
				if ( '-1' === days ) {
					expires = '';
				} else {
					var date = new Date();
					date.setTime( date.getTime() + ( days * 24 * 60 * 60 * 1000 ) );
					expires = ';expires=' + date.toGMTString();
				}
			} else {
				expires = ';expires=Thu, 01 Jan 1970 00:00:01 GMT';
			}

			// Write the cookie.
			document.cookie = name + '=' + value + expires + ';path=/;samesite=strict' + secure;
		},

		/**
		 * Retrieve cookie.
		 *
		 * @since 1.3.3
		 *
		 * @param {string} name Cookie name.
		 *
		 * @returns {string|null} Cookie value or null when it doesn't exist.
		 */
		getCookie: function( name ) {

			var nameEQ = name + '=',
				ca     = document.cookie.split( ';' );

			for ( var i = 0; i < ca.length; i++ ) {
				var c = ca[i];
				while ( ' ' === c.charAt( 0 ) ) {
					c = c.substring( 1, c.length );
				}
				if ( 0 === c.indexOf( nameEQ ) ) {
					return c.substring( nameEQ.length, c.length );
				}
			}

			return null;
		},

		/**
		 * Delete cookie.
		 *
		 * @since 1.3.3
		 *
		 * @param {string} name Cookie name.
		 */
		removeCookie: function( name ) {

			app.createCookie( name, '', -1 );
		},

		/**
		 * Get user browser preferred language.
		 *
		 * @since 1.5.2
		 *
		 * @returns {string} Language code.
		 */
		getFirstBrowserLanguage: function() {
			var nav = window.navigator,
				browserLanguagePropertyKeys = [ 'language', 'browserLanguage', 'systemLanguage', 'userLanguage' ],
				i,
				language;

			// Support for HTML 5.1 "navigator.languages".
			if ( Array.isArray( nav.languages ) ) {
				for ( i = 0; i < nav.languages.length; i++ ) {
					language = nav.languages[ i ];
					if ( language && language.length ) {
						return language;
					}
				}
			}

			// Support for other well known properties in browsers.
			for ( i = 0; i < browserLanguagePropertyKeys.length; i++ ) {
				language = nav[ browserLanguagePropertyKeys[ i ] ];
				if ( language && language.length ) {
					return language;
				}
			}

			return '';
		},

		/**
		 * Asynchronously fetches country code using current IP
		 * and executes a callback provided with a country code parameter.
		 *
		 * @since 1.5.2
		 *
		 * @param {Function} callback Executes once the fetch is completed.
		 */
		currentIpToCountry: function( callback ) {

			var fallback = function() {

				$.get( 'https://ipapi.co/jsonp', function() {}, 'jsonp' )
					.always( function( resp ) {
						var countryCode = ( resp && resp.country ) ? resp.country : '';
						if ( ! countryCode ) {
							var lang = app.getFirstBrowserLanguage();
							countryCode = lang.indexOf( '-' ) > -1 ? lang.split( '-' ).pop() : '';
						}
						callback( countryCode );
					} );
			};

			$.get( 'https://geo.wpforms.com/v3/geolocate/json' )
				.done( function( resp ) {
					if ( resp && resp.country_iso ) {
						callback( resp.country_iso );
					} else {
						fallback();
					}
				} )
				.fail( function( resp ) {
					fallback();
				} );
		},

		/**
		 * Form submit.
		 *
		 * @since 1.5.3
		 * @since 1.7.6 Allow canceling form submission.
		 *
		 * @param {jQuery} $form Form element.
		 */
		formSubmit: function( $form ) {

			// Form element was passed from vanilla JavaScript.
			if ( ! ( $form instanceof jQuery ) ) {
				$form = $( $form );
			}

			app.saveTinyMCE();

			let event = WPFormsUtils.triggerEvent( $form, 'wpformsBeforeFormSubmit', [ $form ] );

			// Allow callbacks on `wpformsBeforeFormSubmit` to cancel form submission by triggering `event.preventDefault()`.
			if ( event.isDefaultPrevented() ) {
				app.restoreSubmitButton( $form, $form.closest( '.wpforms-container' ) );

				return;
			}

			if ( $form.hasClass( 'wpforms-ajax-form' ) && typeof FormData !== 'undefined' ) {
				app.formSubmitAjax( $form );
			} else {
				app.formSubmitNormal( $form );
			}
		},

		/**
		 * Restore default state for the form submit button.
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $form      Form element.
		 * @param {jQuery} $container Form container.
		 */
		restoreSubmitButton: function( $form, $container ) {

			let $submit     = $form.find( '.wpforms-submit' ),
				submitText  = $submit.data( 'submit-text' );

			if ( submitText ) {
				$submit.text( submitText );
			}

			$submit.prop( 'disabled', false );

			WPFormsUtils.triggerEvent( $form, 'wpformsFormSubmitButtonRestore', [ $form, $submit ] );

			$container.css( 'opacity', '' );
			$form.find( '.wpforms-submit-spinner' ).hide();
		},

		/**
		 * Normal form submit with page reload.
		 *
		 * @since 1.5.3
		 *
		 * @param {jQuery} $form Form element.
		 */
		formSubmitNormal: function( $form ) {

			if ( ! $form.length ) {
				return;
			}

			var $submit     = $form.find( '.wpforms-submit' ),
				recaptchaID = $submit.get( 0 ).recaptchaID;

			if ( ! app.empty( recaptchaID ) || recaptchaID === 0 ) {
				$submit.get( 0 ).recaptchaID = false;
			}

			$form.get( 0 ).submit();
		},

		/**
		 * Does the form have a captcha?
		 *
		 * @since 1.7.6
		 *
		 * @param {jQuery} $form Form element.
		 *
		 * @returns {boolean} True when the form has a captcha.
		 */
		formHasCaptcha: function( $form ) {

			if ( ! $form || ! $form.length ) {
				return false;
			}

			if ( typeof hcaptcha === 'undefined' && typeof grecaptcha === 'undefined' && typeof turnstile === 'undefined' ) {
				return false;
			}

			const $captchaContainer = $form.find( '.wpforms-recaptcha-container' );

			return Boolean( $captchaContainer.length );
		},

		/**
		 * Reset form captcha.
		 *
		 * @since 1.5.3
		 * @since 1.6.4 Added hCaptcha support.
		 *
		 * @param {jQuery} $form Form element.
		 */
		resetFormRecaptcha: function( $form ) {

			if ( ! app.formHasCaptcha( $form ) ) {
				return;
			}

			var $captchaContainer = $form.find( '.wpforms-recaptcha-container' ),
				apiVar,
				recaptchaID;

			if ( $captchaContainer.hasClass( 'wpforms-is-hcaptcha' ) ) {
				apiVar = hcaptcha;
			} else if ( $captchaContainer.hasClass( 'wpforms-is-turnstile' ) ) {
				apiVar = turnstile;
			} else {
				apiVar = grecaptcha;
			}

			// Check for invisible recaptcha first.
			recaptchaID = $form.find( '.wpforms-submit' ).get( 0 ).recaptchaID;

			// Check for hcaptcha/recaptcha v2, if invisible recaptcha is not found.
			if ( app.empty( recaptchaID ) && recaptchaID !== 0 ) {
				recaptchaID = $form.find( '.g-recaptcha' ).data( 'recaptcha-id' );
			}

			// Reset captcha.
			if ( ! app.empty( recaptchaID ) || recaptchaID === 0 ) {
				apiVar.reset( recaptchaID );
			}
		},

		/**
		 * Console log AJAX error.
		 *
		 * @since 1.5.3
		 *
		 * @param {string} error Error text (optional).
		 */
		consoleLogAjaxError: function( error ) {

			if ( error ) {
				console.error( 'WPForms AJAX submit error:\n%s', error ); // eslint-disable-line no-console
			} else {
				console.error( 'WPForms AJAX submit error' ); // eslint-disable-line no-console
			}
		},

		/**
		 * Display form AJAX errors.
		 *
		 * @since 1.5.3
		 *
		 * @param {jQuery} $form Form element.
		 * @param {object} errors Errors in format { general: { generalErrors }, field: { fieldErrors } }.
		 */
		displayFormAjaxErrors: function( $form, errors ) {

			if ( 'string' === typeof errors ) {
				app.displayFormAjaxGeneralErrors( $form, errors );
				return;
			}

			errors = errors && ( 'errors' in errors ) ? errors.errors : null;

			if ( app.empty( errors ) || ( app.empty( errors.general ) && app.empty( errors.field ) ) ) {
				app.consoleLogAjaxError();
				return;
			}

			if ( ! app.empty( errors.general ) ) {
				app.displayFormAjaxGeneralErrors( $form, errors.general );
			}

			if ( ! app.empty( errors.field ) ) {
				app.displayFormAjaxFieldErrors( $form, errors.field );
			}
		},

		/**
		 * Display form AJAX general errors that cannot be displayed using jQuery Validation plugin.
		 *
		 * @since 1.5.3
		 *
		 * @param {jQuery} $form Form element.
		 * @param {object} errors Errors in format { errorType: errorText }.
		 */
		displayFormAjaxGeneralErrors: function( $form, errors ) {

			if ( ! $form || ! $form.length ) {
				return;
			}

			if ( app.empty( errors ) ) {
				return;
			}

			const formId = $form.data( 'formid' );

			if ( app.isModernMarkupEnabled() ) {
				$form.attr( {
					'aria-invalid': 'true',
					'aria-errormessage': '',
				} );
			}

			// Safety net for random errors thrown by a third-party code. Should never be used intentionally.
			if ( 'string' === typeof errors ) {

				const roleAttr = app.isModernMarkupEnabled() ? ' role="alert"' : '',
					errPrefix = app.isModernMarkupEnabled() ? `<span class="wpforms-hidden">${wpforms_settings.formErrorMessagePrefix}</span>` : '';

				$form
					.find( '.wpforms-submit-container' )
					.before( `<div class="wpforms-error-container"${roleAttr}>${errPrefix}${errors}</div>` );
				return;
			}

			$.each( errors, function( type, html ) {
				switch ( type ) {
					case 'header':
						$form.prepend( html );
						break;
					case 'footer':
						$form.find( '.wpforms-submit-container' ).before( html );
						break;
					case 'recaptcha':
						$form.find( '.wpforms-recaptcha-container' ).append( html );
						break;
				}

				if ( app.isModernMarkupEnabled() ) {
					const errormessage = $form.attr( 'aria-errormessage' ) || '';

					$form.attr( 'aria-errormessage', `${errormessage} wpforms-${formId}-${type}-error` );
				}
			} );
		},

		/**
		 * Clear forms AJAX general errors that cannot be cleared using jQuery Validation plugin.
		 *
		 * @since 1.5.3
		 *
		 * @param {jQuery} $form Form element.
		 */
		clearFormAjaxGeneralErrors: function( $form ) {

			$form.find( '.wpforms-error-container' ).remove();
			$form.find( '#wpforms-field_recaptcha-error' ).remove();

			// Clear form accessibility attributes.
			if ( app.isModernMarkupEnabled() ) {
				$form.attr( {
					'aria-invalid': 'false',
					'aria-errormessage': '',
				} );
			}
		},

		/**
		 * Display form AJAX field errors using jQuery Validation plugin.
		 *
		 * @since 1.5.3
		 *
		 * @param {jQuery} $form Form element.
		 * @param {object} errors Errors in format { fieldName: errorText }.
		 */
		displayFormAjaxFieldErrors: function( $form, errors ) {

			if ( ! $form || ! $form.length ) {
				return;
			}

			if ( app.empty( errors ) ) {
				return;
			}

			var validator = $form.data( 'validator' );

			if ( ! validator ) {
				return;
			}

			validator.showErrors( errors );

			if ( ! app.formHasCaptcha( $form ) ) {
				validator.focusInvalid();
			}
		},

		/**
		 * Submit a form using AJAX.
		 *
		 * @since 1.5.3
		 * @since 1.7.6 Allow canceling Ajax submission.
		 *
		 * @param {jQuery} $form Form element.
		 *
		 * @returns {JQueryXHR|JQueryDeferred} Promise like object for async callbacks.
		 */
		formSubmitAjax: function( $form ) {

			if ( ! $form.length ) {
				return $.Deferred().reject(); // eslint-disable-line new-cap
			}

			var $container = $form.closest( '.wpforms-container' ),
				$spinner = $form.find( '.wpforms-submit-spinner' ),
				$confirmationScroll,
				formData,
				args;

			$container.css( 'opacity', 0.6 );
			$spinner.show();

			app.clearFormAjaxGeneralErrors( $form );

			formData = new FormData( $form.get( 0 ) );
			formData.append( 'action', 'wpforms_submit' );
			formData.append( 'page_url', window.location.href );
			formData.append( 'page_title', wpforms_settings.page_title );
			formData.append( 'page_id', wpforms_settings.page_id );

			args = {
				type       : 'post',
				dataType   : 'json',
				url        : wpforms_settings.ajaxurl,
				data       : formData,
				cache      : false,
				contentType: false,
				processData: false,
			};

			args.success = function( json ) {

				if ( ! json ) {
					app.consoleLogAjaxError();
					return;
				}

				if ( json.data && json.data.action_required ) {
					$form.trigger( 'wpformsAjaxSubmitActionRequired', json );
					return;
				}

				if ( ! json.success ) {
					app.resetFormRecaptcha( $form );
					app.displayFormAjaxErrors( $form, json.data );
					$form.trigger( 'wpformsAjaxSubmitFailed', json );
					app.setCurrentPage( $form, json.data );
					return;
				}

				$form.trigger( 'wpformsAjaxSubmitSuccess', json );

				if ( ! json.data ) {
					return;
				}

				if ( json.data.redirect_url ) {
					$form.trigger( 'wpformsAjaxSubmitBeforeRedirect', json );
					window.location = json.data.redirect_url;
					return;
				}

				if ( json.data.confirmation ) {
					$container.html( json.data.confirmation );
					$confirmationScroll = $container.find( 'div.wpforms-confirmation-scroll' );

					$container.trigger( 'wpformsAjaxSubmitSuccessConfirmation', json );

					if ( $confirmationScroll.length ) {
						app.animateScrollTop( $confirmationScroll.offset().top - 100 );
					}
				}
			};

			args.error = function( jqHXR, textStatus, error ) {

				app.consoleLogAjaxError( error );

				$form.trigger( 'wpformsAjaxSubmitError', [ jqHXR, textStatus, error ] );
			};

			args.complete = function( jqHXR, textStatus ) {

				/*
				 * Do not make form active if the action is required or
				 * if the ajax request was successful and the form has a redirect.
				 */
				if (
					jqHXR.responseJSON &&
					jqHXR.responseJSON.data &&
					(
						jqHXR.responseJSON.data.action_required ||
						( textStatus === 'success' && jqHXR.responseJSON.data.redirect_url )
					)
				) {
					return;
				}

				app.restoreSubmitButton( $form, $container );

				$form.trigger( 'wpformsAjaxSubmitCompleted', [ jqHXR, textStatus ] );
			};

			let event = WPFormsUtils.triggerEvent( $form, 'wpformsAjaxBeforeSubmit', [ $form ] );

			// Allow callbacks on `wpformsAjaxBeforeSubmit` to cancel Ajax form submission by triggering `event.preventDefault()`.
			if ( event.isDefaultPrevented() ) {
				app.restoreSubmitButton( $form, $container );

				return $.Deferred().reject(); // eslint-disable-line new-cap
			}

			return $.ajax( args );
		},

		/**
		 * Display page with error for multiple page form.
		 *
		 * @since 1.7.9
		 *
		 * @param {jQuery} $form Form element.
		 * @param {object} $json Error json.
		 */
		setCurrentPage: function( $form, $json ) {

			// Return for one-page forms.
			if ( $form.find( '.wpforms-page-indicator' ).length === 0 ) {
				return;
			}

			let $errorPages = [];

			$form.find( '.wpforms-page' ).each( function( index, el ) {

				if ( $( el ).find( '.wpforms-has-error' ).length >= 1 ) {

					return $errorPages.push( $( el ) );
				}
			} );

			// Get first page with error.
			const $currentPage = $errorPages.length > 0 ? $errorPages[0] : $form.find( '.wpforms-page-1' );
			const currentPage = $currentPage.data( 'page' );

			let $page,
				action = 'prev';

			// If error is on the first page, or we have general errors among others, go to first page.
			if ( currentPage === 1 || $json.errors.general.footer !== undefined ) {
				$page = $form.find( '.wpforms-page-1' ).next();
			} else {
				$page  = $currentPage.next().length !== 0 ? $currentPage.next() : $currentPage.prev();
				action = $currentPage.next().length !== 0 ? 'prev' : 'next';
			}

			// Take the page from which navigate to error.
			const $nextBtn = $page.find( '.wpforms-page-next' ),
				page = $page.data( 'page' );

			// Imitate navigation to the page with error.
			app.navigateToPage( $nextBtn, action, page, $form, $( '.wpforms-page-' + page ) );
		},

		/**
		 * Scroll to position with animation.
		 *
		 * @since 1.5.3
		 *
		 * @param {number} position Position (in pixels) to scroll to,
		 * @param {number} duration Animation duration.
		 * @param {Function} complete Function to execute after animation is complete.
		 *
		 * @returns {JQueryPromise} Promise object for async callbacks.
		 */
		animateScrollTop: function( position, duration, complete ) {

			duration = duration || 1000;
			complete = typeof complete === 'function' ? complete : function() {};
			return $( 'html, body' ).animate( { scrollTop: parseInt( position, 10 ) }, { duration: duration, complete: complete } ).promise();
		},

		/**
		 * Save tinyMCE.
		 *
		 * @since 1.7.0
		 */
		saveTinyMCE: function() {

			if ( typeof tinyMCE !== 'undefined' ) {
				tinyMCE.triggerSave();
			}
		},

		/**
		 * Check if object is a function.
		 *
		 * @deprecated 1.6.7
		 *
		 * @since 1.5.8
		 *
		 * @param {mixed} object Object to check if it is function.
		 *
		 * @returns {boolean} True if object is a function.
		 */
		isFunction: function( object ) {

			return !! ( object && object.constructor && object.call && object.apply );
		},

		/**
		 * Compare times.
		 *
		 * @since 1.7.1
		 *
		 * @param {string} time1 Time 1.
		 * @param {string} time2 Time 2.
		 *
		 * @returns {boolean} True if time1 is greater than time2.
		 */
		compareTimesGreaterThan: function( time1, time2 ) {

			// Properly format time: add space before AM/PM, make uppercase.
			time1 = time1.replace( /(am|pm)/g, ' $1' ).toUpperCase();
			time2 = time2.replace( /(am|pm)/g, ' $1' ).toUpperCase();

			var time1Date = Date.parse( '01 Jan 2021 ' + time1 ),
				time2Date = Date.parse( '01 Jan 2021 ' + time2 );

			return time1Date >= time2Date;
		},

		/**
		 * Determine whether the modern markup setting is enabled.
		 *
		 * @since 1.8.1
		 *
		 * @returns {boolean} True if modern markup is enabled.
		 */
		isModernMarkupEnabled: function() {

			return !! wpforms_settings.isModernMarkupEnabled;
		},
	};

	return app;

}( document, window, jQuery ) );

// Initialize.
wpforms.init();
