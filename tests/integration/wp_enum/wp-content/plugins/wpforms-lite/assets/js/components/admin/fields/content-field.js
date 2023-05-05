/* global wpforms_builder, wpf, tinymce, quicktags */

'use strict';

/**
 * WPForms Content Field builder functions.
 *
 * @since 1.7.8
 */
var WPForms = window.WPForms || {};

WPForms.Admin                      = WPForms.Admin || {};
WPForms.Admin.Builder              = WPForms.Admin.Builder || {};
WPForms.Admin.Builder.ContentField = WPForms.Admin.Builder.ContentField || ( function( document, window, $ ) {

	let app = {

		/**
		 * Duplicated field id helper variable.
		 *
		 * @since 1.7.8
		 *
		 * @type {string|undefined}
		 */
		duplicatedFieldContent: undefined,

		/**
		 * CSS class for the div ending field content preview.
		 *
		 * @since 1.7.8
		 *
		 * @type {string}
		 */
		contentPreviewEndClass: 'wpforms-field-content-preview-end',

		/**
		 * The id of the layout field where user just added some field.
		 *
		 * @since 1.7.8
		 *
		 * @type {bool|int}
		 */
		updatedLayoutFieldId: false,

		/**
		 * Stores tinymce.PluginManager instance.
		 *
		 * @since 1.7.8
		 *
		 * @type {object|tinymce.PluginManager}
		 */
		_pluginManager: {},

		/**
		 * Textarea ID.
		 *
		 * @since 1.7.8
		 *
		 * @param {int} id Field ID.
		 *
		 * @returns {string} Textarea ID string without # symbol.
		 */
		textareaId: function( id ) {

			return `wpforms-field-option-${id}-content`;
		},

		/**
		 * Content wrap ID.
		 *
		 * @since 1.7.8
		 *
		 * @param {int} id Field ID.
		 *
		 * @returns {string} Content wrap ID.
		 */
		contentWrap: function( id ) {

			return `wp-wpforms-field-option-${id}-content-wrap`;
		},

		/**
		 * Start the engine.
		 *
		 * @since 1.7.8
		 */
		init: function() {

			app.bindInitInstanceCallback();
			$( app.ready );
		},

		/**
		 * Initialized once the DOM is fully loaded.
		 *
		 * @since 1.7.8
		 */
		ready: function() {

			app.setPluginManager();

			$( '#wpforms-builder' )
				.on( 'wpformsFieldAdd', app.onWpformsFieldAdd )
				.on( 'wpformsFieldMove', app.onWpformsFieldMove )
				.on( 'wpformsBeforeFieldDuplicate', app.onWpformsBeforeFieldDuplicate )
				.on( 'wpformsFieldDuplicated', app.onWpformsFieldDuplicated )
				.on( 'wpformsBeforeSave', app.onWpformsBeforeSave )
				.on( 'click', '.wpforms-content-button-update-preview.update-preview', app.updatePreview )
				.on( 'click', '.wpforms-content-button-expand-editor.expand-editor', app.expandEditor )
				.on( 'wpformsLayoutAfterReceiveFieldToColumn', app.onWpformsLayoutAfterReceiveFieldToColumn )
				.on( 'wpformsLayoutAfterUpdateColumnsData', app.layoutChanged )
				.on( 'click', '.wpforms-expandable-editor .insert-media', app.onInsertMediaButtonClicked )
				.on( 'click', '.wpforms-expandable-editor .mce-toolbar button, .wpforms-expandable-editor .quicktags-toolbar input', app.onContentUpdated )
				.on( 'input', '.wpforms-expandable-editor .wp-editor-area', app.onContentUpdated )
				.on( 'click', '.wpforms-expandable-editor .wp-switch-editor.switch-html', app.setTextareaVisible )
				.on( 'click', '.wpforms-panel-content-wrap .wpforms-field', app.hideImageToolbar );
		},

		/**
		 * Reset editor when field is added first time or duplicated.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event Event object.
		 * @param {int}    id    Editor ID.
		 * @param {string} type  Field type.
		 */
		onWpformsFieldAdd: function( event, id, type ) {

			app.updateContentFieldInColumns();
			app.hasEditor( type ) && app.resetEditor( id, app.duplicatedFieldContent );
		},

		/**
		 * When someone puts any field in column, change the flag to mark the action started.
		 *
		 * @since 1.7.8
		 *
		 * @param {Event}  event wpformsLayoutAfterReceiveFieldToColumn event.
		 * @param {object} data  Data object.
		 */
		onWpformsLayoutAfterReceiveFieldToColumn: function( event, data ) {

			let $layoutField = data.column.closest( '.wpforms-field.wpforms-field-layout' );

			if ( $layoutField.length > 0 ) {
				app.updatedLayoutFieldId = $layoutField.data( 'field-id' );
			}
		},

		/**
		 * When a layout field is updated (preset is changed, inner fields are added/moved, etc.) - reset content fields inside.
		 *
		 * @since 1.7.8
		 *
		 * @param {Event}  event jQuery.Event object.
		 * @param {object} data  Layout field data.
		 */
		layoutChanged: function( event, data ) {

			// If the reason of the layout change was the duplication of content field inside layout, do not proceed.
			if ( typeof app.duplicatedFieldContent !== 'undefined' ) {
				return;
			}

			if ( data.fieldId > 0 ) {
				app.resetFieldsInLayout( data.fieldId );
			}
		},

		/**
		 * If adding field to layout's column has been triggered, reset all editor fields in the same layout.
		 *
		 * Without this, editor fields gets empty.
		 *
		 * @since 1.7.8
		 */
		updateContentFieldInColumns: function() {

			if ( app.updatedLayoutFieldId ) {
				app.resetFieldsInLayout( app.updatedLayoutFieldId );
				app.updatedLayoutFieldId = false;
			}
		},

		/**
		 * Reset editor on field move.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event Event object.
		 * @param {object} ui    UI object.
		 */
		onWpformsFieldMove: function( event, ui ) {

			if ( ui.item.data( 'field-type' ) === 'layout' ) {
				app.resetFieldsInLayout( ui.item.data( 'field-id' ) );
				return;
			}

			if ( ! app.hasEditor( ui.item.data( 'field-type' ) ) ) {
				return;
			}

			let id           = ui.item.data( 'field-id' ),
				currentValue = app.getEditorContent( id );

			app.resetEditor( id, currentValue );
			app.updateContentFieldInColumns();
		},

		/**
		 * Traverse all content fields and reset only those which are inside layout field with given ID.
		 *
		 * @param {int} layoutFieldId Layout field ID.
		 */
		resetFieldsInLayout: function( layoutFieldId ) {

			$( '.wpforms-field-content.wpforms-field' ).each(
				function() {
					let $fieldPreview = $( this ),
						editorID      = $fieldPreview.data( 'field-id' );

					if ( WPForms.Admin.Builder.FieldLayout.columnsHasFieldID( layoutFieldId, editorID ) ) {
						app.resetEditor( editorID, app.getEditorContent( editorID ) );
					}
				}
			);
		},

		/**
		 * Store temporary field value in variable duplicatedFieldContent before field has been moved.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event  Event object.
		 * @param {int}    id     ID of the field which will be duplicated.
		 * @param {jQuery} $field Field object.
		 */
		onWpformsBeforeFieldDuplicate: function( event, id, $field ) {

			if ( $field.data( 'field-type' ) !== 'content' ) {
				return;
			}

			let $settings = $( `.wpforms-field-has-tinymce[data-field-id=${id}]` );

			app.renderPreview( $settings, id );
			app.duplicatedFieldContent = $field.find( '.wpforms-field-content-preview' ).html().replace( `<div class="${app.contentPreviewEndClass}"></div>`, '' );
		},

		/**
		 * Reset duplicatedFieldContent variable when the field duplication is done.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event      Event object.
		 * @param {int}    id         ID of the field which will be duplicated.
		 * @param {jQuery} $field     Field object.
		 * @param {int}    newFieldId ID of newly created field.
		 * @param {jQuery} $newField  New field object.
		 */
		onWpformsFieldDuplicated: function( event, id, $field, newFieldId, $newField ) {

			app.duplicatedFieldContent = undefined;

			if ( $field.data( 'field-type' ) === 'layout' ) {
				app.resetFieldsInLayout( id );
				app.resetFieldsInLayout( newFieldId );
			}
		},

		/**
		 * Callback triggered before form is going to be saved.
		 *
		 * @since 1.7.8
		 */
		onWpformsBeforeSave: function() {

			// Sanitize each textarea before saving the value.
			$( '.wpforms-field-has-tinymce textarea.wp-editor-area' ).each(
				function() {
					$( this ).val( wpf.sanitizeHTML( $( this ).val(), wpforms_builder.content_field.allowed_html ) );
				}
			);

			// Render preview of each content field.
			$( '.wpforms-field-has-tinymce' ).each(
				function() {
					app.renderPreview( null, $( this ).data( 'field-id' ) );
				}
			);
		},

		/**
		 * Callback for update preview on button click.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event Event object.
		 */
		updatePreview: function( event ) {

			event.preventDefault();

			app.renderPreview( $( this ).closest( '.wpforms-field-has-tinymce' ) );
		},

		/**
		 * Re-render field preview.
		 *
		 * @since 1.7.8
		 *
		 * @param {jQuery|null} $settings Content field settings element.
		 * @param {int|null}    fieldId   Field ID.
		 */
		renderPreview: function( $settings, fieldId = null ) {

			if ( typeof $settings !== 'object' && typeof fieldId !== 'number' ) {
				console.log( 'Cannot update preview. ContentField.renderPreview requires valid $settings object or valid fieldId' );
				return;
			}

			let id       = fieldId > 0 ? fieldId : $settings.data( 'field-id' ),
				$preview = $( `#wpforms-field-${id}` ).find( '.wpforms-field-content-preview' ),
				value    = app.parseShortcode( wpf.sanitizeHTML( app.getContentFromActiveView( id ), wpforms_builder.content_field.allowed_html ) );

			$preview.html( `${value}<div class="${app.contentPreviewEndClass}"></div>` );
		},

		/**
		 * Get content depending on which view is active (HTML or WYSIWYG).
		 *
		 * @since 1.7.8
		 *
		 * @param {int} id Field ID.
		 *
		 * @returns {string} Textarea or editor content.
		 */
		getContentFromActiveView: function( id ) {

			if ( $( `#${app.contentWrap( id )}` ).hasClass( 'html-active' ) ) {
				return wpf.wpautop( $( `#${app.textareaId( id )}` ).val() );
			}

			return app.getEditorContent( id );
		},

		/**
		 * Get content from editor.
		 *
		 * Tries to get value from editor. In cases when it is not loaded yet, retrieves value from textarea.
		 *
		 * @since 1.7.8
		 *
		 * @param {int} id The field ID.
		 *
		 * @returns {string} Editors content.
		 */
		getEditorContent: function( id ) {

			let editor = tinymce.get( app.textareaId( id ) );

			if ( editor ) {
				return editor.getContent();
			}

			return $( `#${app.textareaId( id )}` ).val();
		},

		/**
		 * Expand and collapse editor.
		 *
		 * @since 1.7.8
		 *
		 * @param {object} event Event object.
		 */
		expandEditor: function( event ) {

			event.preventDefault();

			let className           = 'wpforms-content-editor-expanded',
				$this               = $( this ),
				$panelSidebar       = $this.closest( '.wpforms-panel-sidebar' ),
				$tabContent         = $this.closest( '.wpforms-field-options.wpforms-tab-content' ),
				$fieldOptionContent = $this.closest( '.wpforms-field-option.wpforms-field-has-tinymce' ),
				$actionButtons      = $this.closest( '.wpforms-field-content-action-buttons' ),
				$sidebarWrapper     = $this.closest( '.wpforms-expandable-editor' ),
				$editorClear        = $sidebarWrapper.next( '.wpforms-expandable-editor-clear' ),
				editorHeight        = $sidebarWrapper.outerHeight( true ) + 20;

			$this.toggleClass( className ); // Add/remove class wpforms-content-editor-expanded to button.

			// Make action button wrapper same width as sidebar width.
			if ( $this.hasClass( className ) ) {
				$actionButtons.width( $sidebarWrapper.width() );
				$editorClear.css( 'margin-bottom', `${editorHeight}px` );
			} else {
				$editorClear.css( 'margin-bottom', 0 );
			}

			// Add/remove class wpforms-content-editor-expanded to editor/sidebar elements which needs different styling when expanded.
			[ $panelSidebar, $tabContent, $fieldOptionContent ].forEach(
				function( element ) {

					if ( $this.hasClass( className ) ) {
						element.addClass( className );
						$this.find( 'span' ).text( wpforms_builder.content_field.collapse );

						return;
					}
					$( `.${className}` ).removeClass( className );
					$( 'button.expand-editor' ).each(
						function() {
							$( this ).find( 'span' ).text( wpforms_builder.content_field.expand );
						}
					);
				}
			);
		},

		/**
		 * Set plugin manager instance.
		 *
		 * Create fake tinymce instance and use it to instantiate tinymce.PluginManager.
		 *
		 * @since 1.7.8
		 */
		setPluginManager: function() {

			if ( $( '#wpforms-builder' ).length > 0 && typeof tinymce !== 'undefined' ) {
				let $fakeTextarea = $( document.createElement( 'textarea' ) ),
					textareaId    = 'wpforms-content-field-fake-div';

				$fakeTextarea.attr( 'id', textareaId ).css( 'display', 'none' ).appendTo( 'body' );

				/* eslint-disable camelcase */
				tinymce.init(
					{
						selector: `#${textareaId}`,
						init_instance_callback: function( instance ) {
							app._pluginManager = tinymce.PluginManager.get( 'wpeditimage' )( instance );
						},
					}
				);
				/* eslint-enable */
			}
		},

		/**
		 * Callback for TinyMCE init_instance_callback.
		 *
		 * @since 1.7.8
		 */
		bindInitInstanceCallback: function() {

			window.wpformsContentFieldTinyMCECallback = function( editor ) {

				if ( ! editor ) {
					return;
				}

				editor.on(
					'dirty',
					app.onContentUpdated
				);
				editor.on(
					'keyup',
					app.onContentUpdated
				);
			};

		},

		/**
		 * On content updated callback.
		 *
		 * @since 1.7.8
		 */
		onContentUpdated: function() {

			app.showUpdatePreviewButton( $( this ).attr( 'id' ) );
		},

		/**
		 * Set textarea visible when user clicks Text editor tab.
		 *
		 * @since 1.7.9
		 */
		setTextareaVisible: function() {

			let textareaID = $( this ).data( 'wp-editor-id' );

			$( `#${textareaID}` ).css( 'visibility', 'visible' );
		},

		/**
		 * Hide image toolbar when user click other field.
		 *
		 * @since 1.7.8
		 */
		hideImageToolbar: function() {
			$( '.mce-toolbar-grp.mce-inline-toolbar-grp' ).hide();
		},

		/**
		 * On insert media button clicked.
		 *
		 * @since 1.7.8
		 */
		onInsertMediaButtonClicked: function() {

			const textareaId = app.textareaId( $( this ).closest( '.wpforms-field-has-tinymce' ).data( 'field-id' ) );

			app.showUpdatePreviewButton( textareaId );
		},

		/**
		 * Flag saved state and show update preview button when editor content has been updated.
		 *
		 * @since 1.7.8
		 *
		 * @param {int} textareaId Textarea ID.
		 */
		showUpdatePreviewButton: function( textareaId ) {

			/**
			 Builder does not see changes in TinyMCE field so if the user edits content and then is going to leave
			 the editor, it is not prompting to save. Let's reset savedState on TinyMCE change.
			 */
			wpf.savedState = false;

			/**
			 * Unhide "Update preview" button.
			 */
			$( `#${textareaId}` ).closest( '.wpforms-field-option' ).find( '.update-preview' ).show();
		},

		/**
		 * Reset editor.
		 *
		 * Removes editor and adds it again.
		 *
		 * @since 1.7.8
		 *
		 * @param {int}    id    Field ID.
		 * @param {string} value Editor value to set after the reset.
		 */
		resetEditor: function( id, value ) {

			let textareaId = app.textareaId( id ),
				editor     = tinymce.get( textareaId );

			if ( editor ) {
				tinymce.execCommand( 'mceRemoveEditor', false, textareaId );
			} else {
				app.cleanEditorWrap( id );
			}

			app.initTinyMCE( id, value );
		},

		/**
		 * Initialize TinyMCE editor instance.
		 *
		 * @since 1.7.8
		 *
		 * @param {int}              id         Field ID.
		 * @param {undefined|string} value      Editor's value.
		 */
		initTinyMCE: function( id, value ) {

			let textareaId = app.textareaId( id );

			/*
			 Heads up, if you are going to edit editor settings, bear in mind editor is instantiated in two places:
			 - PHP instance in \WPForms\Admin\Builder\Traits\ContentInput::get_content_editor
			 - JS instance in WPForms.Admin.Builder.ContentField.initTinyMCE
			 */
			/* eslint-disable camelcase */
			tinymce.init(
				{
					selector: `#${textareaId}`,
					textarea_name: `fields[${id}][content]`,
					media_buttons: true,
					drag_drop_upload: true,
					relative_urls: false,
					remove_script_host: false,
					menubar: false,
					branding: false,
					object_resizing: false,
					height: wpforms_builder.content_field.editor_height,
					plugins: wpforms_builder.content_field.content_editor_plugins.join(),
					toolbar: wpforms_builder.content_field.content_editor_toolbar.join(),
					imagetools_toolbar: 'rotateleft rotateright | flipv fliph | editimage imageoptions',
					content_css: wpforms_builder.content_field.content_editor_css_url + '?' + new Date().getTime(), // https://www.tiny.cloud/docs-4x/configure/content-appearance/#browsercaching
					invalid_elements: wpforms_builder.content_field.invalid_elements,
					wp_shortcut_labels: window.wp?.editor?.getDefaultSettings?.()?.tinymce?.wp_shortcut_labels,
					body_class: wpforms_builder.content_field.body_class,
					init_instance_callback: function( instance ) {

						instance.setContent( typeof value !== 'undefined' ? value : wpforms_builder.content_field.editor_default_value );
						window.wpformsContentFieldTinyMCECallback( instance );
						app.setWrapperClasses( tinymce.$( `#${app.contentWrap( id )}` ) );
						quicktags(
							{
								id: textareaId,
								buttons: wpforms_builder.content_field.quicktags_buttons,
							}
						);
					},
				}
			);
			/* eslint-enable */
		},

		/**
		 * Checks if field has tinymce editor and editor object is instantiated.
		 *
		 * @since 1.7.8
		 *
		 * @param {string} type Field type.
		 *
		 * @returns {boolean} If has editor.
		 */
		hasEditor: function( type ) {

			return wpforms_builder.content_input.supported_field_types.includes( type ) && typeof tinymce !== 'undefined';
		},

		/**
		 * Clean editor wrap element from tinymce element which are about to be replaced with new one.
		 *
		 * @since 1.7.8
		 *
		 * @param {int} id Field ID.
		 */
		cleanEditorWrap: function( id ) {

			let textarea    = $( `#${app.textareaId( id )}` ),
				$wrap       = textarea.closest( '.wp-editor-wrap' ),
				editorTools = ( wp.template( 'wpforms-content-editor-tools' ) )( { optionId: `option-${id}` } );

			textarea.css( 'display', 'block' );
			app.setWrapperClasses( $wrap ).empty()
				.append( editorTools )
				.append( textarea )
				.attr( 'id', `${app.contentWrap( id )}` );
		},

		/**
		 * Set editor wrapper classes.
		 *
		 * @since 1.7.8
		 *
		 * @param {jQuery} $wrapper Editor wrapper element.
		 *
		 * @returns {jQuery} Editor wrapper element.
		 */
		setWrapperClasses: function( $wrapper ) {

			return $wrapper.addClass( 'tmce-active tmce-initialized' ).removeClass( 'html-active' );
		},

		/**
		 * Parse string content and replace [caption] shortcode.
		 *
		 * @since 1.7.8
		 *
		 * @param {string|undefined} content Text content to parse.
		 *
		 * @returns {string|undefined} Parsed text.
		 */
		parseShortcode: function( content ) {

			if ( typeof content === 'undefined' ) {
				return content;
			}

			return app._pluginManager?._do_shcode?.( content ) ?? content;
		},
	};

	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.ContentField.init();
