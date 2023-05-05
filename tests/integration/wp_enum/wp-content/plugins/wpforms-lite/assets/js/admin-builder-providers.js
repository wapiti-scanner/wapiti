/* global wpforms_builder_providers, wpforms_builder, wpf */

( function( $ ) {

	var s;

	var WPFormsProviders = {

		settings: {
			spinner: '<i class="wpforms-loading-spinner wpforms-loading-inline"></i>',
			spinnerWhite: '<i class="wpforms-loading-spinner wpforms-loading-inline wpforms-loading-white"></i>',
		},

		/**
		 * Start the engine.
		 *
		 * @since 1.0.0
		 */
		init: function() {

			s = this.settings;

			// Document ready.
			$( WPFormsProviders.ready );

			WPFormsProviders.bindUIActions();
		},

		/**
		 * Document ready.
		 *
		 * @since 1.1.1
		 */
		ready: function() {

			// Setup/cache some vars not available before.
			s.form = $( '#wpforms-builder-form' );
		},

		/**
		 * Element bindings.
		 *
		 * @since 1.0.0
		 */
		bindUIActions: function() {

			// Delete connection.
			$( document ).on( 'click', '.wpforms-provider-connection-delete', function( e ) {
				WPFormsProviders.connectionDelete( this, e );
			} );

			// Add new connection.
			$( document ).on( 'click', '.wpforms-provider-connections-add', function( e ) {
				WPFormsProviders.connectionAdd( this, e );
			} );

			// Add new provider account.
			$( document ).on( 'click', '.wpforms-provider-account-add button', function( e ) {
				WPFormsProviders.accountAdd( this, e );
			} );

			// Select provider account.
			$( document ).on( 'change', '.wpforms-provider-accounts select', function( e ) {
				WPFormsProviders.accountSelect( this, e );
			} );

			// Select account list.
			$( document ).on( 'change', '.wpforms-provider-lists select', function( e ) {
				WPFormsProviders.accountListSelect( this, e );
			} );

			$( document ).on( 'wpformsPanelSwitch', function( e, targetPanel ) {
				WPFormsProviders.providerPanelConfirm( targetPanel );
			} );

			// Alert users if they save a form and do not configure required
			// fields.
			$( document ).on( 'wpformsSaved', function() {

				var providerAlerts = [];
				var $connectionBlocks = $( '#wpforms-panel-providers' ).find( '.wpforms-connection-block' );

				if ( ! $connectionBlocks.length ) {
					return;
				}

				$connectionBlocks.each( function() {
					var requiredEmpty = false,
						providerName;
					$( this ).find( 'table span.required' ).each( function() {
						var $element = $( this ).parent().parent().find( 'select' );
						if ( $element.val() === '' ) {
							requiredEmpty = true;
						}
					} );
					if ( requiredEmpty ) {
						var $titleArea = $( this ).closest( '.wpforms-panel-content-section' ).find( '.wpforms-panel-content-section-title' ).clone();
						$titleArea.find( 'button' ).remove();
						providerName = $titleArea.text().trim();
						var msg  = wpforms_builder.provider_required_flds;

						if ( -1 < providerAlerts.indexOf( providerName ) ) {
							return;
						}
						$.alert( {
							title: wpforms_builder.heads_up,
							content: msg.replace( '{provider}', providerName ),
							icon: 'fa fa-exclamation-circle',
							type: 'orange',
							buttons: {
								confirm: {
									text: wpforms_builder.ok,
									btnClass: 'btn-confirm',
									keys: [ 'enter' ],
								},
							},
						} );
						providerAlerts.push( providerName );
					}
				} );
			} );
		},

		/**
		 * Delete provider connection
		 *
		 * @since 1.0.0
		 */
		connectionDelete: function( el, e ) {
			e.preventDefault();

			var $this = $( el );

			$.confirm( {
				title: false,
				content: wpforms_builder_providers.confirm_connection,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							var $section = $this.closest( '.wpforms-panel-content-section' );

							$this.closest( '.wpforms-provider-connection' ).remove();

							if ( ! $section.find( '.wpforms-provider-connection' ).length ) {
								$section.find( '.wpforms-builder-provider-connections-default' ).removeClass( 'wpforms-hidden' );
							}
						},
					},
					cancel: {
						text: wpforms_builder.cancel,
					},
				},
			} );
		},

		/**
		 * Add new provider connection.
		 *
		 * @since 1.0.0
		 */
		connectionAdd: function( el, e ) {
			e.preventDefault();

			var $this        = $( el ),
				$connections = $this.parent().parent(),
				$container   = $this.parent(),
				provider     = $this.data( 'provider' ),
				type         = $this.data( 'type' ),
				namePrompt   = wpforms_builder_providers.prompt_connection,
				nameField    = '<input autofocus="" type="text" id="provider-connection-name" placeholder="' + wpforms_builder_providers.prompt_placeholder + '">',
				nameError    = '<p class="error">' + wpforms_builder_providers.error_name + '</p>',
				modalContent = namePrompt + nameField + nameError;

			modalContent = modalContent.replace( /%type%/g, type );

			$.confirm( {
				title: false,
				content: modalContent,
				icon: 'fa fa-info-circle',
				type: 'blue',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {
							var name = this.$content.find( 'input#provider-connection-name' ).val().trim();
							var error = this.$content.find( '.error' );
							if ( name === '' ) {
								error.show();
								return false;
							} else {

								// Disable button.
								WPFormsProviders.inputToggle( $this, 'disable' );

								// Fire AJAX.
								var data =  {
									action  : 'wpforms_provider_ajax_' + provider,
									provider: provider,
									task    : 'new_connection',
									name    : name,
									id      : s.form.data( 'id' ),
									nonce   : wpforms_builder.nonce,
								};
								WPFormsProviders.fireAJAX( $this, data, function( res ) {
									if ( res.success ) {
										$connections.find( '.wpforms-builder-provider-connections-default' ).addClass( 'wpforms-hidden' );
										$connections.find( '.wpforms-provider-connections' ).prepend( res.data.html );

										// Process and load the accounts if they exist.
										var $connection = $connections.find( '.wpforms-provider-connection' ).first();
										if ( $connection.find( '.wpforms-provider-accounts option:selected' ) ) {
											$connection.find( '.wpforms-provider-accounts option' ).first().prop( 'selected', true );
											$connection.find( '.wpforms-provider-accounts select' ).trigger( 'change' );
										}
									} else {
										WPFormsProviders.errorDisplay( res.data.error, $container );
									}
								} );
							}
						},
					},
					cancel: {
						text: wpforms_builder.cancel,
					},
				},
			} );
		},

		/**
		 * Add and authorize provider account.
		 *
		 * @since 1.0.0
		 */
		accountAdd: function( el, e ) {
			e.preventDefault();

			var $this       = $( el ),
				provider    = $this.data( 'provider' ),
				$connection = $this.closest( '.wpforms-provider-connection' ),
				$container  = $this.parent(),
				$fields     = $container.find( ':input' ),
				errors      = WPFormsProviders.requiredCheck( $fields, $container );

			// Disable button.
			WPFormsProviders.inputToggle( $this, 'disable' );

			// Bail if we have any errors.
			if ( errors ) {
				$this.prop( 'disabled', false ).find( 'i' ).remove();
				return false;
			}

			// Fire AJAX.
			var data = {
				action       : 'wpforms_provider_ajax_' + provider,
				provider     : provider,
				connection_id: $connection.data( 'connection_id' ),
				task         : 'new_account',
				data         : WPFormsProviders.fakeSerialize( $fields ),
			};
			WPFormsProviders.fireAJAX( $this, data, function( res ) {
				if ( res.success ) {
					$container.nextAll( '.wpforms-connection-block' ).remove();
					$container.nextAll( '.wpforms-conditional-block' ).remove();
					$container.after( res.data.html );
					$container.slideUp();
					$connection.find( '.wpforms-provider-accounts select' ).trigger( 'change' );
				} else {
					WPFormsProviders.errorDisplay( res.data.error, $container );
				}
			} );
		},

		/**
		 * Selecting a provider account
		 *
		 * @since 1.0.0
		 */
		accountSelect: function( el, e ) {
			e.preventDefault();

			var $this       = $( el ),
				$connection = $this.closest( '.wpforms-provider-connection' ),
				$container  = $this.parent(),
				provider    = $connection.data( 'provider' );

			// Disable select, show loading.
			WPFormsProviders.inputToggle( $this, 'disable' );

			// Remove any blocks that might exist as we prep for new account.
			$container.nextAll( '.wpforms-connection-block' ).remove();
			$container.nextAll( '.wpforms-conditional-block' ).remove();

			if ( ! $this.val() ) {

				// User selected to option to add new account.
				$connection.find( '.wpforms-provider-account-add input' ).val( '' );
				$connection.find( '.wpforms-provider-account-add' ).slideDown();
				WPFormsProviders.inputToggle( $this, 'enable' );

			} else {

				$connection.find( '.wpforms-provider-account-add' ).slideUp();

				// Fire AJAX.
				var data = {
					action       : 'wpforms_provider_ajax_' + provider,
					provider     : provider,
					connection_id: $connection.data( 'connection_id' ),
					task         : 'select_account',
					account_id   : $this.find( ':selected' ).val(),
				};
				WPFormsProviders.fireAJAX( $this, data, function( res ) {
					if ( res.success ) {
						$container.after( res.data.html );

						// Process first list found.
						$connection.find( '.wpforms-provider-lists option' ).first().prop( 'selected', true );
						$connection.find( '.wpforms-provider-lists select' ).trigger( 'change' );
					} else {
						WPFormsProviders.errorDisplay( res.data.error, $container );
					}
				} );
			}
		},

		/**
		 * Selecting a provider account list.
		 *
		 * @since 1.0.0
		 */
		accountListSelect: function( el, e ) {
			e.preventDefault();

			var $this       = $( el ),
				$connection = $this.closest( '.wpforms-provider-connection' ),
				$container  = $this.parent(),
				provider    = $connection.data( 'provider' );

			// Disable select, show loading.
			WPFormsProviders.inputToggle( $this, 'disable' );

			// Remove any blocks that might exist as we prep for new account.
			$container.nextAll( '.wpforms-connection-block' ).remove();
			$container.nextAll( '.wpforms-conditional-block' ).remove();

			var data = {
				action       : 'wpforms_provider_ajax_' + provider,
				provider     : provider,
				connection_id: $connection.data( 'connection_id' ),
				task         : 'select_list',
				account_id   : $connection.find( '.wpforms-provider-accounts option:selected' ).val(),
				list_id      : $this.find( ':selected' ).val(),
				form_id      : s.form.data( 'id' ),
			};

			WPFormsProviders.fireAJAX( $this, data, function( res ) {
				if ( res.success ) {
					$container.after( res.data.html );

					// Re-init tooltips for new fields.
					wpf.initTooltips();
				} else {
					WPFormsProviders.errorDisplay( res.data.error, $container );
				}
			} );
		},

		/**
		 * Confirm form save before loading Provider panel.
		 * If confirmed, save and reload panel.
		 *
		 * @since 1.0.0
		 */
		providerPanelConfirm: function( targetPanel ) {

			wpforms_panel_switch = true;
			if ( targetPanel === 'providers' && ! s.form.data( 'revision' ) ) {
				if ( wpf.savedState != wpf.getFormState( '#wpforms-builder-form' ) ) {
					wpforms_panel_switch = false;
					$.confirm( {
						title: false,
						content: wpforms_builder_providers.confirm_save,
						icon: 'fa fa-info-circle',
						type: 'blue',
						buttons: {
							confirm: {
								text: wpforms_builder.ok,
								btnClass: 'btn-confirm',
								keys: [ 'enter' ],
								action: function() {
									$( '#wpforms-save' ).trigger( 'click' );
									$( document ).on( 'wpformsSaved', function() {
										window.location.href = wpforms_builder_providers.url;
									} );
								},
							},
							cancel: {
								text: wpforms_builder.cancel,
							},
						},
					} );
				}
			}
		},

		//--------------------------------------------------------------------//
		// Helper functions.
		//--------------------------------------------------------------------//

		/**
		 * Fire AJAX call.
		 *
		 * @since 1.0.0
		 */
		fireAJAX: function( el, d, success ) {
			var $this = $( el );
			var data = {
				id    : $( '#wpforms-builder-form' ).data( 'id' ),
				nonce : wpforms_builder.nonce,
			};

			$.extend( data, d );
			$.post( wpforms_builder.ajax_url, data, function( res ) {
				success( res );
				WPFormsProviders.inputToggle( $this, 'enable' );
			} ).fail( function( xhr, textStatus, e ) {
				console.log( xhr.responseText );
			} );
		},

		/**
		 * Toggle input with loading indicator.
		 *
		 * @since 1.0.0
		 */
		inputToggle: function( el, status ) {
			var $this = $( el );
			if ( status === 'enable' ) {
				if ( $this.is( 'select' ) ) {
					$this.prop( 'disabled', false ).next( 'i' ).remove();
				} else {
					$this.prop( 'disabled', false ).find( 'i' ).remove();
				}
			} else if ( status === 'disable' ) {
				if ( $this.is( 'select' ) ) {
					$this.prop( 'disabled', true ).after( s.spinner );
				} else {
					$this.prop( 'disabled', true ).prepend( s.spinnerWhite );
				}
			}
		},

		/**
		 * Display error.
		 *
		 * @since 1.0.0
		 */
		errorDisplay: function( msg, location ) {
			location.find( '.wpforms-error-msg' ).remove();
			location.prepend( '<p class="wpforms-alert-danger wpforms-alert wpforms-error-msg">' + msg + '</p>' );
		},

		/**
		 * Check for required fields.
		 *
		 * @since 1.0.0
		 */
		requiredCheck: function( fields, location ) {
			var error = false;

			// Remove any previous errors.
			location.find( '.wpforms-alert-required' ).remove();

			// Loop through input fields and check for values.
			fields.each( function( index, el ) {
				if ( $( el ).hasClass( 'wpforms-required' ) && $( el ).val().length === 0 ) {
					$( el ).addClass( 'wpforms-error' );
					error = true;
				} else {
					$( el ).removeClass( 'wpforms-error' );
				}
			} );
			if ( error ) {
				location.prepend( '<p class="wpforms-alert-danger wpforms-alert wpforms-alert-required">' + wpforms_builder_providers.required_field + '</p>' );
			}
			return error;
		},

		/**
		 * Pseudo serializing. Fake it until you make it.
		 *
		 * @since 1.0.0
		 */
		fakeSerialize: function( els ) {
			var fields = els.clone();

			fields.each( function( index, el ) {
				if ( $( el ).data( 'name' ) ) {
					$( el ).attr( 'name', $( el ).data( 'name' ) );
				}
			} );
			return fields.serialize();
		},
	};

	WPFormsProviders.init();
} )( jQuery );
