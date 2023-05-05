/* global tinyMCE, vpEditorView */
( function ( $, wp, vpEditorView ) {
	wp.mce = wp.mce || {};
	if ( 'undefined' === typeof wp.mce.views ) {
		return;
	}
	wp.mce.videopress_wp_view_renderer = {
		shortcode_string: 'videopress',
		shortcode_data: {},
		defaults: {
			w: '',
			at: '',
			permalink: true,
			hd: false,
			loop: false,
			freedom: false,
			autoplay: false,
			flashonly: false,
		},
		coerce: wp.media.coerce,
		template: wp.template( 'videopress_iframe_vnext' ),
		getContent: function () {
			var urlargs = 'for=' + encodeURIComponent( vpEditorView.home_url_host ),
				named = this.shortcode.attrs.named,
				options,
				key,
				width;

			for ( key in named ) {
				switch ( key ) {
					case 'at':
						if ( parseInt( named[ key ], 10 ) ) {
							urlargs += '&' + key + '=' + parseInt( named[ key ], 10 );
						} // Else omit, as it's the default.
						break;
					case 'permalink':
						if ( 'false' === named[ key ] ) {
							urlargs += '&' + key + '=0';
						} // Else omit, as it's the default.
						break;
					case 'hd':
					case 'loop':
					case 'autoplay':
						if ( 'true' === named[ key ] ) {
							urlargs += '&' + key + '=1';
						} // Else omit, as it's the default.
						break;
					default:
						// Unknown parameters?  Ditch it!
						break;
				}
			}

			options = {
				width: vpEditorView.content_width,
				height: vpEditorView.content_width * 0.5625,
				guid: this.shortcode.attrs.numeric[ 0 ],
				urlargs: urlargs,
			};

			if ( typeof named.w !== 'undefined' ) {
				width = parseInt( named.w, 10 );
				if ( width >= vpEditorView.min_content_width && width < vpEditorView.content_width ) {
					options.width = width;
					options.height = parseInt( width * 0.5625, 10 );
				}
			}

			options.ratio = 100 * ( options.height / options.width );

			return this.template( options );
		},
		edit: function ( data ) {
			var shortcode_data = wp.shortcode.next( this.shortcode_string, data ),
				named = shortcode_data.shortcode.attrs.named,
				editor = tinyMCE.activeEditor,
				renderer = this,
				oldRenderFormItem = tinyMCE.ui.FormItem.prototype.renderHtml;

			/**
			 * Override TextBox renderHtml to support html5 attrs.
			 * @link https://github.com/tinymce/tinymce/pull/2784
			 *
			 * @returns {string}
			 */
			tinyMCE.ui.TextBox.prototype.renderHtml = function () {
				var self = this,
					settings = self.settings,
					element = document.createElement( settings.multiline ? 'textarea' : 'input' ),
					extraAttrs = [
						'rows',
						'spellcheck',
						'maxLength',
						'size',
						'readonly',
						'min',
						'max',
						'step',
						'list',
						'pattern',
						'placeholder',
						'required',
						'multiple',
					],
					i,
					key;

				for ( i = 0; i < extraAttrs.length; i++ ) {
					key = extraAttrs[ i ];
					if ( typeof settings[ key ] !== 'undefined' ) {
						element.setAttribute( key, settings[ key ] );
					}
				}

				if ( settings.multiline ) {
					element.innerText = self.state.get( 'value' );
				} else {
					element.setAttribute( 'type', settings.subtype ? settings.subtype : 'text' );
					element.setAttribute( 'value', self.state.get( 'value' ) );
				}

				element.id = self._id;
				element.className = self.classes;
				element.setAttribute( 'hidefocus', 1 );
				if ( self.disabled() ) {
					element.disabled = true;
				}

				return element.outerHTML;
			};

			tinyMCE.ui.FormItem.prototype.renderHtml = function () {
				_.each(
					vpEditorView.modal_labels,
					function ( value, key ) {
						if ( value === this.settings.items.text ) {
							this.classes.add( 'videopress-field-' + key );
						}
					},
					this
				);

				if (
					_.contains(
						[
							vpEditorView.modal_labels.hd,
							vpEditorView.modal_labels.permalink,
							vpEditorView.modal_labels.autoplay,
							vpEditorView.modal_labels.loop,
							vpEditorView.modal_labels.freedom,
							vpEditorView.modal_labels.flashonly,
						],
						this.settings.items.text
					)
				) {
					this.classes.add( 'videopress-checkbox' );
				}
				return oldRenderFormItem.call( this );
			};

			/**
			 * Populate the defaults.
			 */
			_.each(
				this.defaults,
				function ( value, key ) {
					named[ key ] = this.coerce( named, key );
				},
				this
			);

			/**
			 * Declare the fields that will show in the popup when editing the shortcode.
			 */
			editor.windowManager.open( {
				title: vpEditorView.modal_labels.title,
				id: 'videopress-shortcode-settings-modal',
				width: 520,
				height: 240,
				body: [
					{
						type: 'textbox',
						disabled: true,
						name: 'guid',
						label: vpEditorView.modal_labels.guid,
						value: shortcode_data.shortcode.attrs.numeric[ 0 ],
					},
					{
						type: 'textbox',
						subtype: 'number',
						min: vpEditorView.min_content_width, // The `min` may supported be in the future. https://github.com/tinymce/tinymce/pull/2784
						name: 'w',
						label: vpEditorView.modal_labels.w,
						value: named.w,
					},
					{
						type: 'textbox',
						subtype: 'number',
						min: 0, // The `min` may supported be in the future. https://github.com/tinymce/tinymce/pull/2784
						name: 'at',
						label: vpEditorView.modal_labels.at,
						value: named.at,
					},
					{
						type: 'checkbox',
						name: 'hd',
						label: vpEditorView.modal_labels.hd,
						checked: named.hd,
					},
					{
						type: 'checkbox',
						name: 'permalink',
						label: vpEditorView.modal_labels.permalink,
						checked: named.permalink,
					},
					{
						type: 'checkbox',
						name: 'autoplay',
						label: vpEditorView.modal_labels.autoplay,
						checked: named.autoplay,
					},
					{
						type: 'checkbox',
						name: 'loop',
						label: vpEditorView.modal_labels.loop,
						checked: named.loop,
					},
					{
						type: 'checkbox',
						name: 'freedom',
						label: vpEditorView.modal_labels.freedom,
						checked: named.freedom,
					},
					{
						type: 'checkbox',
						name: 'flashonly',
						label: vpEditorView.modal_labels.flashonly,
						checked: named.flashonly,
					},
				],
				onsubmit: function ( e ) {
					var args = {
						tag: renderer.shortcode_string,
						type: 'single',
						attrs: {
							named: _.pick( e.data, _.keys( renderer.defaults ) ),
							numeric: [ e.data.guid ],
						},
					};

					if ( '0' === args.attrs.named.at ) {
						args.attrs.named.at = '';
					}

					_.each(
						renderer.defaults,
						function ( value, key ) {
							args.attrs.named[ key ] = this.coerce( args.attrs.named, key );

							if ( value === args.attrs.named[ key ] ) {
								delete args.attrs.named[ key ];
							}
						},
						renderer
					);

					editor.insertContent( wp.shortcode.string( args ) );
				},
				onopen: function ( e ) {
					var prefix = 'mce-videopress-field-';
					_.each( [ 'w', 'at' ], function ( value ) {
						e.target.$el
							.find( '.' + prefix + value + ' .mce-container-body' )
							.append(
								'<span class="' +
									prefix +
									'unit ' +
									prefix +
									'unit-' +
									value +
									'">' +
									vpEditorView.modal_labels[ value + '_unit' ]
							);
					} );
					$( 'body' ).addClass( 'modal-open' );
				},
				onclose: function () {
					$( 'body' ).removeClass( 'modal-open' );
				},
			} );

			// Set it back to its original renderer.
			tinyMCE.ui.FormItem.prototype.renderHtml = oldRenderFormItem;
		},
	};
	wp.mce.views.register( 'videopress', wp.mce.videopress_wp_view_renderer );

	// Extend the videopress one to also handle `wpvideo` instances.
	wp.mce.wpvideo_wp_view_renderer = _.extend( {}, wp.mce.videopress_wp_view_renderer, {
		shortcode_string: 'wpvideo',
	} );
	wp.mce.views.register( 'wpvideo', wp.mce.wpvideo_wp_view_renderer );
} )( jQuery, wp, vpEditorView );
