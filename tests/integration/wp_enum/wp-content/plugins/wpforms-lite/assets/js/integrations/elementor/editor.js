/* global wpformsElementorVars, elementor, elementorFrontend */

'use strict';

/**
 * WPForms integration with Elementor in the editor.
 *
 * @since 1.6.0
 * @since 1.6.2 Moved frontend integration to `wpforms-elementor-frontend.js`
 */
var WPFormsElementor = window.WPFormsElementor || ( function( document, window, $ ) {

	/**
	 * Runtime variables.
	 *
	 * @since 1.6.2
	 *
	 * @type {object}
	 */
	var vars = {};

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

			app.events();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.6.0
		 */
		events: function() {

			// Widget events.
			$( window ).on( 'elementor/frontend/init', function( event, id, instance ) {

				// Widget buttons click.
				elementor.channels.editor.on( 'elementorWPFormsAddFormBtnClick', app.addFormBtnClick );

				// Widget frontend events.
				elementorFrontend.hooks.addAction( 'frontend/element_ready/wpforms.default', app.widgetPreviewEvents );

				// Initialize widget controls.
				elementor.hooks.addAction( 'panel/open_editor/widget/wpforms', app.widgetPanelOpen );

			} );
		},

		/**
		 * Widget events.
		 *
		 * @since 1.6.2
		 *
		 * @param {jQuery} $scope The current element wrapped with jQuery.
		 */
		widgetPreviewEvents: function( $scope ) {

			$scope
				.on( 'click', '.wpforms-btn', app.addFormBtnClick )
				.on( 'click', '.wpforms-admin-no-forms-container a', app.clickLinkInPreview )
				.on( 'change', '.wpforms-elementor-form-selector select', app.selectFormInPreview )
				.on( 'click mousedown focus keydown submit', '.wpforms-container *', app.disableEvents );

			app.updateSameForms( $scope );
		},

		/**
		 * Update all the same forms on the preview.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} $scope The current element wrapped with jQuery.
		 */
		updateSameForms: function( $scope ) {

			var elementId = $scope.data( 'id' ),
				$formContainer = $scope.find( '.wpforms-container' ),
				formContainerHtml = $formContainer.html(),
				formContainerId = $formContainer.attr( 'id' );

			$scope
				.closest( '.elementor-inner' )
				.find( '.elementor-widget-wpforms:not(.elementor-element-' + elementId + ')' )
				.each( function() {

					var $anotherFormContainer = $( this ).find( '.wpforms-container' );

					if ( $anotherFormContainer.attr( 'id' ) === formContainerId ) {
						$anotherFormContainer.html( formContainerHtml );
					}
				} );
		},

		/**
		 * Initialize widget controls when widget is activated.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} panel Panel object.
		 * @param {object} model Model object.
		 */
		widgetPanelOpen: function( panel, model ) {

			vars.widgetId = model.attributes.id;
			vars.formId = model.attributes.settings.attributes.form_id;

			app.widgetPanelInit( panel );

			app.widgetPanelObserver.init( panel );
		},

		/**
		 * Initialize widget controls when widget is activated.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} panel Panel object.
		 */
		widgetPanelInit: function( panel ) {

			var	$formSelectControl = panel.$el.find( '.elementor-control.elementor-control-form_id' ),
				$formSelect = $formSelectControl.find( 'select' ),
				$addFormNoticeControl = panel.$el.find( '.elementor-control.elementor-control-add_form_notice' ),
				$testFormNoticeControl = panel.$el.find( '.elementor-control.elementor-control-test_form_notice' );

			// Update form select options if it is available after adding the form.
			if ( vars.formSelectOptions ) {
				$formSelect.html( vars.formSelectOptions );
			}

			// Update form select value.
			if ( vars.formId && vars.formId !== '' ) {
				$formSelect.val( vars.formId );
			}

			// Hide not needed controls.
			if ( $formSelect.find( 'option' ).length > 0 ) {
				$addFormNoticeControl.hide();
			} else {
				$formSelectControl.hide();
				$testFormNoticeControl.hide();
			}

			// Show needed controls.
			if ( parseInt( $formSelect.val(), 10 ) > 0 ) {
				$testFormNoticeControl.show();
			}

			// Select form.
			panel.$el.find( '.elementor-control.elementor-control-form_id' ).on( 'change', 'select', function() {

				// Update `vars.formId` to be able to restore selected value after options update.
				vars.formId = $( this ).val();
			} );

			// Click on the `Edit the selected form` link.
			panel.$el.find( '.elementor-control.elementor-control-edit_form' ).on( 'click', 'a', app.editFormLinkClick );
		},

		/**
		 * The observer needed to re-init controls when the widget panel section and tabs switches.
		 *
		 * @since 1.6.3
		 *
		 * @member {object}
		 */
		widgetPanelObserver: {

			/**
			 * Initialize observer.
			 *
			 * @since 1.6.3
			 *
			 * @param {object} panel Panel object.
			 */
			init: function( panel ) {

				// Skip if observer for current widget already initialized.
				if ( vars.observerWidgetId === vars.widgetId ) {
					return;
				}

				// Disconnect previous widget observer.
				if ( typeof vars.observer !== 'undefined' && typeof vars.observer.disconnect === 'function' ) {
					vars.observer.disconnect();
				}

				var obs = {
					targetNode  : panel.$el.find( '#elementor-panel-content-wrapper' )[0],
					config      : {
						childList: true,
						subtree: true,
						attributes: true,
					},
				};

				app.widgetPanelObserver.panel = panel;

				obs.observer = new MutationObserver( app.widgetPanelObserver.callback );
				obs.observer.observe( obs.targetNode, obs.config );

				vars.observerWidgetId = vars.widgetId;
				vars.observer = obs.observer;
			},

			/**
			 * Observer callback.
			 *
			 * @since 1.6.3
			 *
			 * @param {Array} mutationsList Mutation list.
			 */
			callback: function( mutationsList ) {

				var mutation,
					quit = false;

				for ( var i in mutationsList ) {
					mutation = mutationsList[ i ];

					if ( mutation.type === 'childList' && mutation.addedNodes.length > 0 ) {
						quit = app.widgetPanelObserver.callbackMutationChildList( mutation );
					}

					if ( mutation.type === 'attributes' ) {
						quit = app.widgetPanelObserver.callbackMutationAttributes( mutation );
					}

					if ( quit ) {
						return;
					}
				}
			},

			/**
			 * Process 'childList' mutation.
			 *
			 * @since 1.6.3
			 *
			 * @param {MutationRecord} mutation Mutation record.
			 *
			 * @returns {boolean} True if detect needed node.
			 */
			callbackMutationChildList: function( mutation ) {

				var addedNodes = mutation.addedNodes || [],
					node;

				for ( var n in addedNodes ) {
					node = addedNodes[ n ];

					if ( node && node.classList && node.classList.contains( 'elementor-control-section_form' ) ) {
						app.widgetPanelInit( app.widgetPanelObserver.panel );
						return true;
					}
				}

				return false;
			},

			/**
			 * Process 'attributes' mutation.
			 *
			 * @since 1.6.3
			 *
			 * @param {MutationRecord} mutation Mutation record.
			 *
			 * @returns {boolean} True if detect needed target.
			 */
			callbackMutationAttributes: function( mutation ) {

				if (
					mutation.target &&
					mutation.target.classList &&
					mutation.target.classList.contains( 'elementor-tab-control-content' )
				) {
					app.widgetPanelInit( app.widgetPanelObserver.panel );

					return true;
				}

				return false;
			},
		},

		/**
		 * Edit selected form button click event handler.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event Event object.
		 */
		editFormLinkClick: function( event ) {

			app.findFormSelector( event );
			app.openBuilderPopup( vars.$select.val() );
		},

		/**
		 * Add a new form button click event handler.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event Event object.
		 */
		addFormBtnClick: function( event ) {

			app.findFormSelector( event );
			app.openBuilderPopup( 0 );
		},

		/**
		 * Find and store the form selector control wrapped in jQuery object.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event Event object.
		 */
		findFormSelector: function( event ) {

			vars.$select = event && event.$el ?
				event.$el.closest( '#elementor-controls' ).find( 'select[data-setting="form_id"]' ) :
				window.parent.jQuery( '#elementor-controls select[data-setting="form_id"]' );
		},

		/**
		 * Preview: Form selector event handler.
		 *
		 * @since 1.6.2
		 */
		selectFormInPreview: function() {

			vars.formId = $( this ).val();

			app.findFormSelector();
			vars.$select.val( vars.formId ).trigger( 'change' );
		},

		/**
		 * Preview: Click on the link event handler.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event Event object.
		 */
		clickLinkInPreview: function( event ) {

			if ( event.target && event.target.href ) {
				window.open( event.target.href, '_blank', 'noopener,noreferrer' );
			}
		},

		/**
		 * Disable events.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event Event object.
		 *
		 * @returns {boolean} Always false.
		 */
		disableEvents: function( event ) {

			event.preventDefault();
			event.stopImmediatePropagation();

			return false;
		},

		/**
		 * Open builder popup.
		 *
		 * @since 1.6.2
		 *
		 * @param {number} formId Form id. 0 for create new form.
		 */
		openBuilderPopup: function( formId ) {

			formId = parseInt( formId || '0', 10 );

			if ( ! vars.$popup ) {

				// We need to add popup markup to the editor top document.
				var $elementor = window.parent.jQuery( '#elementor-editor-wrapper' ),
					popupTpl = wp.template( 'wpforms-builder-elementor-popup' );

				$elementor.after( popupTpl() );
				vars.$popup = $elementor.siblings( '#wpforms-builder-elementor-popup' );
			}

			var url = formId > 0 ? wpformsElementorVars.edit_form_url + formId : wpformsElementorVars.add_form_url,
				$iframe = vars.$popup.find( 'iframe' );

			app.builderCloseButtonEvent();
			$iframe.attr( 'src', url );
			vars.$popup.fadeIn();
		},

		/**
		 * Close button (inside the form builder) click event.
		 *
		 * @since 1.6.2
		 */
		builderCloseButtonEvent: function() {

			vars.$popup
				.off( 'wpformsBuilderInPopupClose' )
				.on( 'wpformsBuilderInPopupClose', function( e, action, formId ) {

					if ( action !== 'saved' || ! formId ) {
						return;
					}

					app.refreshFormsList( null, formId );
				} );
		},

		/**
		 * Refresh forms list event handler.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} event     Event object.
		 * @param {number} setFormId Set selected form to.
		 */
		refreshFormsList: function( event, setFormId ) {

			if ( event ) {
				event.preventDefault();
			}

			app.findFormSelector();

			var data = {
				action: 'wpforms_admin_get_form_selector_options',
				nonce : wpformsElementorVars.nonce,
			};

			vars.$select.prop( 'disabled', true );

			$.post( wpformsElementorVars.ajax_url, data )
				.done( function( response ) {

					if ( ! response.success ) {
						app.debug( response );
						return;
					}

					vars.formSelectOptions = response.data;
					vars.$select.html( response.data );

					if ( setFormId ) {
						vars.formId = setFormId;
					}

					if ( vars.formId && vars.formId !== '' ) {
						vars.$select.val( vars.formId ).trigger( 'change' );
					}
				} )
				.fail( function( xhr, textStatus ) {

					app.debug( {
						xhr: xhr,
						textStatus: textStatus,
					} );
				} )
				.always( function() {

					if ( ! vars.$select || vars.$select.length < 1 ) {
						return;
					}

					vars.$select.prop( 'disabled', false );

					var $formSelectOptions = vars.$select.find( 'option' ),
						$formSelectControl = vars.$select.closest( '.elementor-control' );

					if ( $formSelectOptions.length > 0 ) {
						$formSelectControl.show();
						$formSelectControl.siblings( '.elementor-control-add_form_notice' ).hide();
					}
					if ( parseInt( vars.$select.val(), 10 ) > 0 ) {
						$formSelectControl.siblings( '.elementor-control-test_form_notice' ).show();
					}
				} );
		},

		/**
		 * Debug output helper.
		 *
		 * @since 1.6.2
		 *
		 * @param {mixed} msg Debug message.
		 */
		debug: function( msg ) {

			if ( app.isDebug() ) {
				console.log( 'WPForms Debug:', msg );
			}
		},

		/**
		 * Is debug mode.
		 *
		 * @since 1.6.2
		 *
		 * @returns {boolean} True if the debug enabled.
		 */
		isDebug: function() {

			return ( ( window.top.location.hash && '#wpformsdebug' === window.top.location.hash ) || wpformsElementorVars.debug );
		},
	};

	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsElementor.init();
