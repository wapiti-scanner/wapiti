/* global wpforms_builder, WPFormsBuilder, WPFormsUtils */

/**
 * Form Builder Fields Drag-n-Drop module.
 *
 * @since 1.7.7
 */

'use strict';

var WPForms = window.WPForms || {};

WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.DragFields = WPForms.Admin.Builder.DragFields || ( function( document, window, $ ) {

	/**
	 * Elements holder.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	let el = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	let vars = {};

	/**
	 * Layout field functions wrapper.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	let fieldLayout;

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	const app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.7
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * DOM is fully loaded.
		 *
		 * @since 1.7.7
		 */
		ready: function() {

			app.setup();
			app.initSortableFields();

			app.events();
		},

		/**
		 * Setup. Prepare some variables.
		 *
		 * @since 1.7.7
		 */
		setup: function() {

			// Cache DOM elements.
			el = {
				$builder:            $( '#wpforms-builder' ),
				$sortableFieldsWrap: $( '#wpforms-panel-fields .wpforms-field-wrap' ),
				$addFieldsButtons:   $( '.wpforms-add-fields-button' ).not( '.not-draggable' ).not( '.warning-modal' ).not( '.education-modal' ),
			};
		},

		/**
		 * Bind events.
		 *
		 * @since 1.7.7
		 */
		events: function() {

			el.$builder
				.on( 'wpformsFieldDragToggle', app.fieldDragToggleEvent );
		},

		/**
		 * Disable drag & drop.
		 *
		 * @since 1.7.1
		 * @since 1.7.7 Moved from admin-builder.js.
		 */
		disableDragAndDrop: function() {

			el.$addFieldsButtons.filter( '.ui-draggable' ).draggable( 'disable' );
			el.$sortableFieldsWrap.sortable( 'disable' );
			el.$sortableFieldsWrap.find( '.wpforms-layout-column.ui-sortable' ).sortable( 'disable' );
		},

		/**
		 * Enable drag & drop.
		 *
		 * @since 1.7.1
		 * @since 1.7.7 Moved from admin-builder.js.
		 */
		enableDragAndDrop: function() {

			el.$addFieldsButtons.filter( '.ui-draggable' ).draggable( 'enable' );
			el.$sortableFieldsWrap.sortable( 'enable' );
			el.$sortableFieldsWrap.find( '.wpforms-layout-column.ui-sortable' ).sortable( 'enable' );
		},

		/**
		 * Show popup in case if field is not draggable, and cancel moving.
		 *
		 * @since 1.7.5
		 * @since 1.7.7 Moved from admin-builder.js.
		 *
		 * @param {jQuery}  $field    A field or list of fields.
		 * @param {boolean} showPopUp Whether the pop-up should be displayed on dragging attempt.
		 */
		fieldDragDisable: function( $field, showPopUp = true ) {

			if ( $field.hasClass( 'ui-draggable-disabled' ) ) {
				$field.draggable( 'enable' );

				return;
			}

			let startTopPosition;

			$field.draggable( {
				revert: true,
				axis: 'y',
				delay: 100,
				opacity: 0.75,
				cursor: 'move',
				start: function( event, ui ) {

					startTopPosition = ui.position.top;
				},
				drag: function( event, ui ) {

					if ( Math.abs( ui.position.top ) - Math.abs( startTopPosition ) > 15 ) {

						if ( showPopUp ) {
							app.youCantReorderFieldPopup();
						}

						return false;
					}
				},
			} );
		},

		/**
		 * Allow field dragging.
		 *
		 * @since 1.7.5
		 * @since 1.7.7 Moved from admin-builder.js.
		 *
		 * @param {jQuery} $field A field or list of fields.
		 */
		fieldDragEnable: function( $field ) {

			if ( $field.hasClass( 'ui-draggable' ) ) {
				return;
			}

			$field.draggable( 'disable' );
		},

		/**
		 * Show the error message in the popup that you cannot reorder the field.
		 *
		 * @since 1.7.1
		 * @since 1.7.7 Moved from admin-builder.js.
		 */
		youCantReorderFieldPopup: function() {

			$.confirm( {
				title: wpforms_builder.heads_up,
				content: wpforms_builder.field_cannot_be_reordered,
				icon: 'fa fa-exclamation-circle',
				type: 'red',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
					},
				},
			} );
		},

		/**
		 * Event handler for `wpformsFieldDragToggle` event.
		 *
		 * @since 1.7.7
		 *
		 * @param {object}  e  Event object.
		 * @param {numeric} id Field ID.
		 */
		fieldDragToggleEvent: function( e, id ) {

			const $field = $( `#wpforms-field-${id}` );

			if (
				$field.hasClass( 'wpforms-field-not-draggable' ) ||
				$field.hasClass( 'wpforms-field-stick' )
			) {
				app.fieldDragDisable( $field );

				return;
			}

			app.fieldDragEnable( $field );
		},

		/**
		 * Initialize sortable fields in the builder form preview area.
		 *
		 * @since 1.7.7
		 */
		initSortableFields: function() {

			app.initSortableContainer( el.$sortableFieldsWrap );

			el.$builder.find( '.wpforms-layout-column' ).each( function() {
				app.initSortableContainer( $( this ) );
			} );

			app.fieldDragDisable( $( '.wpforms-field-not-draggable, .wpforms-field-stick' ) );
			app.initDraggableFields();
		},

		/**
		 * Initialize sortable container with fields.
		 *
		 * @since 1.7.7
		 *
		 * @param {jQuery} $sortable Container to make sortable.
		 */
		initSortableContainer: function( $sortable ) { // eslint-disable-line max-lines-per-function

			const $fieldOptions = $( '#wpforms-field-options' );

			let fieldId,
				fieldType,
				isNewField,
				$fieldOption,
				$prevFieldOption,
				prevFieldId,
				$scrollContainer = $( '#wpforms-panel-fields .wpforms-panel-content-wrap' ),
				currentlyScrolling = false;

			$sortable.sortable( {
				items: '> .wpforms-field:not(.wpforms-field-stick):not(.no-fields-preview)',
				connectWith: '.wpforms-field-wrap, .wpforms-layout-column',
				delay: 100,
				opacity: 0.75,
				cursor: 'move',
				cancel: '.wpforms-field-not-draggable',
				placeholder: 'wpforms-field-drag-placeholder',
				appendTo: '#wpforms-panel-fields',
				zindex: 10000,
				tolerance: 'pointer',
				distance: 1,
				start: function( e, ui ) {

					fieldId = ui.item.data( 'field-id' );
					fieldType = ui.item.data( 'field-type' );
					isNewField = typeof fieldId === 'undefined';
					$fieldOption = $( '#wpforms-field-option-' + fieldId );

					vars.fieldReceived = false;
					vars.fieldRejected = false;
					vars.$sortableStart = $sortable;
					vars.startPosition = ui.item.first().index();
				},
				beforeStop: function( e, ui ) {

					if ( ! vars.glitchChange ) {
						return;
					}

					// Before processing in the `stop` method we need to perform the last check.
					if ( ! fieldLayout.isFieldAllowedInColum( fieldType ) ) {
						vars.fieldRejected = true;
					}
				},
				stop: function( e, ui ) {

					const $field = ui.item.first();

					ui.placeholder.removeClass( 'wpforms-field-drag-not-allowed' );
					$field.removeClass( 'wpforms-field-drag-not-allowed' );

					// Reject not allowed fields.
					if ( vars.fieldRejected ) {
						app.revertMoveFieldToColumn( $field );

						el.$builder.trigger( 'wpformsFieldMoveRejected', [ $field, ui ] );

						return;
					}

					prevFieldId = $field.prev( '.wpforms-field, .wpforms-alert' ).data( 'field-id' );
					$prevFieldOption = $( `#wpforms-field-option-${prevFieldId}` );

					if ( $prevFieldOption.length > 0 ) {
						$prevFieldOption.after( $fieldOption );
					} else {
						$fieldOptions.prepend( $fieldOption );
					}

					// In the case of changing fields order inside the same column,
					// we just need to change the position of the field.
					if ( ! isNewField && $field.closest( '.wpforms-layout-column' ).is( $sortable ) ) {
						fieldLayout.positionFieldInColumn(
							fieldId,
							$field.index() - 1,
							$sortable
						);
					}

					const $layoutField = $field.closest( '.wpforms-field-layout' );

					fieldLayout.fieldOptionsUpdate( null, fieldId );
					fieldLayout.reorderLayoutFieldsOptions( $layoutField );

					if ( ! isNewField ) {
						$field
							.removeClass( 'wpforms-field-dragging' )
							.removeClass( 'wpforms-field-drag-over' );
					}

					$field.attr( 'style', '' );

					el.$builder.trigger( 'wpformsFieldMove', ui );

					vars.fieldReceived = false;
				},
				over: function( e, ui ) { // eslint-disable-line complexity

					const $field = ui.item.first(),
						$target = $( e.target ),
						$placeholder = $target.find( '.wpforms-field-drag-placeholder' ),
						isColumn = $target.hasClass( 'wpforms-layout-column' ),
						targetClass = isColumn ? ' wpforms-field-drag-to-column' : '',
						helper = {
							width: $target.outerWidth(),
							height: $field.outerHeight(),
						};

					fieldId = $field.data( 'field-id' );
					fieldType = $field.data( 'field-type' ) || vars.fieldType;
					isNewField = typeof fieldId === 'undefined';

					// Adjust helper size according to the placeholder size.
					$field
						.addClass( 'wpforms-field-dragging' + targetClass )
						.css( {
							'width': isColumn ? helper.width - 5 : helper.width,
							'height': 'auto',
						} );

					// Adjust placeholder height according to the height of the helper.
					$placeholder
						.removeClass( 'wpforms-field-drag-not-allowed' )
						.css( {
							'height': isNewField ? helper.height + 18 : helper.height,
						} );

					// Drop to this place is not allowed.
					if (
						! fieldLayout.isFieldAllowedInColum( fieldType ) &&
						isColumn
					) {
						$placeholder.addClass( 'wpforms-field-drag-not-allowed' );
						$field.addClass( 'wpforms-field-drag-not-allowed' );
					}

					// Skip if it is the existing field.
					if ( ! isNewField ) {
						return;
					}

					$field
						.addClass( 'wpforms-field-drag-over' )
						.removeClass( 'wpforms-field-drag-out' );
				},
				out: function( e, ui ) {

					const $field = ui.item.first(),
						fieldId = $field.data( 'field-id' ),
						isNewField = typeof fieldId === 'undefined';

					$field
						.removeClass( 'wpforms-field-drag-not-allowed' )
						.removeClass( 'wpforms-field-drag-to-column' );

					if ( vars.fieldReceived ) {
						$field.attr( 'style', '' );

						return;
					}

					// Skip if it is the existing field.
					if ( ! isNewField ) {

						// Remove extra class from the parent layout field.
						// Fixes disappearing of duplicate/delete field icons
						// after moving the field outside the layout field.
						$( ui.sender )
							.closest( '.wpforms-field-layout' )
							.removeClass( 'wpforms-field-child-hovered' );

						return;
					}

					$field
						.addClass( 'wpforms-field-drag-out' )
						.removeClass( 'wpforms-field-drag-over' );
				},
				receive: function( e, ui ) { // eslint-disable-line complexity

					const $field = $( ui.helper || ui.item );

					fieldId = $field.data( 'field-id' );
					fieldType = $field.data( 'field-type' ) || vars.fieldType;

					const isNewField = typeof fieldId === 'undefined',
						isColumn = $sortable.hasClass( 'wpforms-layout-column' );

					// Drop to this place is not allowed.
					if (
						! fieldLayout.isFieldAllowedInColum( fieldType ) &&
						isColumn
					) {
						vars.fieldRejected = true;

						return;
					}

					vars.fieldReceived = true;

					$field.removeClass( 'wpforms-field-drag-over' );

					// Move existing field.
					if ( ! isNewField ) {
						fieldLayout.receiveFieldToColumn(
							fieldId,
							ui.item.index() - 1,
							$field.parent()
						);

						return;
					}

					// Add new field.
					let position = $sortable.data( 'ui-sortable' ).currentItem.index();

					$field
						.addClass( 'wpforms-field-drag-over wpforms-field-drag-pending' )
						.removeClass( 'wpforms-field-drag-out' )
						.append( WPFormsBuilder.settings.spinnerInline )
						.css( 'width', '100%' );

					el.$builder.find( '.wpforms-add-fields .wpforms-add-fields-button' ).prop( 'disabled', true );
					el.$builder.find( '.no-fields-preview' ).remove();

					WPFormsBuilder.fieldAdd(
						vars.fieldType,
						{
							position: isColumn ? position - 1 : position,
							placeholder: $field,
							$sortable: $sortable,
						}
					);

					vars.fieldType = undefined;
				},
				change: function( e, ui ) {

					const $placeholderSortable = ui.placeholder.parent();

					vars.glitchChange = false;

					// In some cases sortable widget display placeholder in wrong sortable instance.
					// It's happens when you drag the field over/out the last column of the last Layout field.
					if (
						! $sortable.is( $placeholderSortable ) &&
						$sortable.hasClass( 'wpforms-field-wrap' ) &&
						$placeholderSortable.hasClass( 'wpforms-layout-column' )
					) {
						vars.glitchChange = true;
					}
				},
				sort: function( e, ui ) {

					if ( currentlyScrolling ) {
						return;
					}

					const scrollAreaHeight = 50,
						mouseYPosition = e.clientY,
						containerOffset = $scrollContainer.offset(),
						containerHeight = $scrollContainer.height(),
						containerBottom = containerOffset.top + containerHeight;

					let operator;

					if (
						mouseYPosition > containerOffset.top &&
						mouseYPosition < ( containerOffset.top + scrollAreaHeight )
					) {
						operator = '-=';
					} else if (
						mouseYPosition > ( containerBottom - scrollAreaHeight ) &&
						mouseYPosition < containerBottom
					) {
						operator = '+=';
					} else {
						return;
					}

					currentlyScrolling = true;

					$scrollContainer.animate(
						{
							scrollTop: operator + containerHeight / 3 + 'px',
						},
						800,
						function() {
							currentlyScrolling = false;
						}
					);
				},
			} );
		},

		/**
		 * Initialize draggable fields buttons.
		 *
		 * @since 1.7.7
		 */
		initDraggableFields: function() {

			el.$addFieldsButtons.draggable( {
				connectToSortable: '.wpforms-field-wrap, .wpforms-layout-column',
				delay: 200,
				cancel: false,
				scroll: false,
				opacity: 0.75,
				appendTo: '#wpforms-panel-fields',
				zindex: 10000,
				helper: function() {

					let $this = $( this ),
						$el = $( '<div class="wpforms-field-drag-out wpforms-field-drag">' );

					vars.fieldType = $this.data( 'field-type' );

					return $el.html( $this.html() );
				},

				start: function( e, ui ) {

					let event = WPFormsUtils.triggerEvent(
						el.$builder,
						'wpformsFieldAddDragStart',
						[ vars.fieldType, ui ]
					);

					// Allow callbacks on `wpformsFieldAddDragStart` to cancel dragging the field
					// by triggering `event.preventDefault()`.
					if ( event.isDefaultPrevented() ) {
						return false;
					}
				},
			} );
		},

		/**
		 * Revert moving the field to the column.
		 *
		 * @since 1.7.7
		 *
		 * @param {jQuery} $field Field object.
		 */
		revertMoveFieldToColumn: function( $field ) {

			const isNewField = $field.data( 'field-id' ) === undefined;

			if ( isNewField ) {

				// Remove the field.
				$field.remove();

				return;
			}

			// Restore existing field on the previous position.
			$field = $field.detach();

			const $fieldInStartPosition = vars.$sortableStart
				.find( '> .wpforms-field' )
				.eq( vars.startPosition );

			$field
				.removeClass( 'wpforms-field-dragging' )
				.removeClass( 'wpforms-field-drag-over' )
				.attr( 'style', '' );

			if ( $fieldInStartPosition.length ) {
				$fieldInStartPosition.before( $field );

				return;
			}

			vars.$sortableStart.append( $field );
		},
	};

	/**
	 * Layout field functions holder.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	fieldLayout = {

		/**
		 * Position field in the column inside the Layout Field.
		 *
		 * @since 1.7.7
		 *
		 * @param {number} fieldId   Field Id.
		 * @param {number} position  The new position of the field inside the column.
		 * @param {jQuery} $sortable Sortable column container.
		 **/
		positionFieldInColumn: function( fieldId, position, $sortable ) {

			if ( ! WPForms.Admin.Builder.FieldLayout ) {
				return;
			}

			WPForms.Admin.Builder.FieldLayout.positionFieldInColumn( fieldId, position, $sortable );
		},

		/**
		 * Receive field to column inside the Layout Field.
		 *
		 * @since 1.7.7
		 *
		 * @param {number} fieldId   Field Id.
		 * @param {number} position  Field position inside the column.
		 * @param {jQuery} $sortable Sortable column container.
		 **/
		receiveFieldToColumn: function( fieldId, position, $sortable ) {

			if ( ! WPForms.Admin.Builder.FieldLayout ) {
				return;
			}

			WPForms.Admin.Builder.FieldLayout.receiveFieldToColumn( fieldId, position, $sortable );
		},

		/**
		 * Update field options according to the position of the field.
		 * Event `wpformsFieldOptionTabToggle` handler.
		 *
		 * @since 1.7.7
		 *
		 * @param {Event}  e       Event.
		 * @param {int}    fieldId Field id.
		 */
		fieldOptionsUpdate: function( e, fieldId ) {

			if ( ! WPForms.Admin.Builder.FieldLayout ) {
				return;
			}

			WPForms.Admin.Builder.FieldLayout.fieldOptionsUpdate( e, fieldId );
		},

		/**
		 * Reorder fields options of the fields in columns.
		 * It is not critical, but it's better to keep some order in the `fields` data array.
		 *
		 * @since 1.7.7
		 *
		 * @param {jQuery} $layoutField Layout field object.
		 */
		reorderLayoutFieldsOptions: function( $layoutField ) {

			if ( ! WPForms.Admin.Builder.FieldLayout ) {
				return;
			}

			WPForms.Admin.Builder.FieldLayout.reorderLayoutFieldsOptions( $layoutField );
		},

		/**
		 * Whether the field type is allowed to be in column.
		 *
		 * @since 1.7.7
		 *
		 * @param {string} fieldType Field ty to check.
		 *
		 * @returns {boolean} True if allowed.
		 */
		isFieldAllowedInColum: function( fieldType ) {

			if ( ! WPForms.Admin.Builder.FieldLayout ) {
				return true;
			}

			return WPForms.Admin.Builder.FieldLayout.isFieldAllowedInColum( fieldType );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.DragFields.init();
