var W3tc_Lightbox = {
	window: jQuery(window),
	container: null,
	options: null,

	create: function() {
		var me = this;

		this.container = jQuery('<div class="' + this.options.id + '"><div class="lightbox-close">' + this.options.close + '</div><div id="w3tc_lightbox_content" class="lightbox-content"></div></div>').css({
			top: 0,
			left: 0,
			width: 0,
			height: 0,
			position: 'fixed',
			'z-index': 9991,
			display: 'none'
		});

		jQuery('body').append(this.container);
		me.resize();
		this.window.resize(function() {
			me.resize();
		});

		this.window.scroll(function() {
			me.resize();
		});

		this.container.find('.lightbox-close').on( 'click', function() {
			me.close();
		});

		jQuery(document).keyup(function(e) {
			if (e.keyCode == 27) { me.close(); }   // esc
		});
	},

	open: function(options) {
		this.options = jQuery.extend({
			id: 'lightbox',
			close: 'Close window',
			width: 0,
			height: 0,
			maxWidth: 0,
			maxHeight: 0,
			minWidth: 0,
			minHeight: 0,
			widthPercent: 0.6,
			heightPercent: 0.8,
			content: null,
			url: null,
			callback: null
		}, options);

		this.create();
		this.resize();

		if (this.options.content) {
			this.content(this.options.content);
		} else if (this.options.url) {
			this.load(this.options.url, this.options.callback);

			if (typeof ga != 'undefined') {
				var w3tc_action = this.options.url.match(/w3tc_action=([^&]+)/);
				if (window.w3tc_ga) {
					if (w3tc_action && w3tc_action[1])
						w3tc_ga('send', 'pageview', 'overlays/' + w3tc_action[1]);
					else {
						var w3tc_action = this.options.url.match(/&(w3tc_[^&]+)&/);
						if (w3tc_action && w3tc_action[1])
							w3tc_ga('send', 'pageview', 'overlays/' + w3tc_action[1]);
					}
				}
			}
		}



		W3tc_Overlay.show();
		this.container.show();
	},

	close: function() {
		if (this.options.onClose)
			this.options.onClose();

		this.container.remove();
		W3tc_Overlay.hide();
	},

	resize: function() {
		var width = (this.options.width ? this.options.width : this.window.width() * this.options.widthPercent);
		var height = (this.options.height ? this.options.height : this.window.height() * this.options.heightPercent);

		if (!this.options.maxWidth)
			this.options.maxWidth = this.window.width();
		if (!this.options.maxHeight)
			this.options.maxHeight = this.window.height();

		if (this.options.maxWidth && width > this.options.maxWidth) {
			width = this.options.maxWidth;
		} else if (width < this.options.minWidth) {
			width = this.options.minWidth;
		}

		if (this.options.maxHeight && height > this.options.maxHeight) {
			height = this.options.maxHeight;
		} else if (height < this.options.minHeight) {
			height = this.options.minHeight;
		}

		this.container.css({
			width: width,
			height: height
		});

		this.container.css({
			top: (this.window.height() / 2 - this.container.outerHeight() / 2)>=0 ? this.window.height() / 2 - this.container.outerHeight() / 2 : 0,
			left: (this.window.width() / 2 - this.container.outerWidth() / 2)>=0 ? this.window.width()  / 2 - this.container.outerWidth()  / 2 : 0
		});

		jQuery('.lightbox-content', this.container).css({
			width: width,
			height: height
		});
	},

	load: function(url, callback) {
		this.content('');
		this.loading(true);
		var me = this;
		jQuery.get(url, {}, function(content) {
			me.loading(false);
			if (content.substr(0, 9) === 'Location ') {
				w3tc_beforeupload_unbind();
				window.location = content.substr(9);
				return;
			}

			me.content(content);
			if (callback) {
				callback.call(this, me);
			}
		});
	},

	/**
	 * adds all controls of the form to the url
	 */
	load_form: function(url, form_selector, callback) {
		data = {}
		var v = jQuery(form_selector).find('input').each(function(i) {
			var name = jQuery(this).attr('name');
			var type = jQuery(this).attr('type');
			if (type == 'radio' || type == 'checkbox' ) {
				if (!jQuery(this).prop('checked'))
					return;
			}

			if (name)
				data[name] = jQuery(this).val();
		});

		this.content('');
		this.loading(true);
		var me = this;
		jQuery.post(url, data, function(content) {
			me.loading(false);
			if (content.substr(0, 9) === 'Location ') {
				w3tc_beforeupload_unbind();
				window.location = content.substr(9);
				return;
			}

			me.content(content);
			if (callback) {
				callback.call(this, me);
			}
		});
	},


	content: function(content) {
		return this.container.find('.lightbox-content').html(content);
	},

	width: function(width) {
		if (width === undefined) {
			return this.container.width();
		} else {
			this.container.css('width', width);
			return this.resize();
		}
	},

	height: function(height) {
		if (height === undefined) {
			return this.container.height();
		} else {
			this.container.css('height', height);
			return this.resize();
		}
	},

	loading: function(loading) {
		if (loading)
			this.container.find('.lightbox-content').addClass('lightbox-loader');
		else
			this.container.find('.lightbox-content').removeClass('lightbox-loader');
	}
};

var W3tc_Overlay = {
	window: jQuery(window),
	container: null,

	create: function() {
		var me = this;

		this.container = jQuery('<div id="overlay" />').css({
			top: 0,
			left: 0,
			width: 0,
			height: 0,
			position: 'fixed',
			'z-index': 9990,
			display: 'none',
			opacity: 0.6
		});

		jQuery('#w3tc').append(this.container);

		this.window.resize(function() {
			me.resize();
		});

		this.window.scroll(function() {
			me.resize();
		});
	},

	show: function() {
		this.create();
		this.resize();
		this.container.show();
	},

	hide: function() {
		this.container.remove();
	},

	resize: function() {
		this.container.css({
			width: this.window.width(),
			height: this.window.height()
		});
	}
};



var w3tc_minify_recommendations_checked = {};

function w3tc_lightbox_minify_recommendations(nonce) {
	W3tc_Lightbox.open({
		width: 1000,
		url: 'admin.php?page=w3tc_minify&w3tc_test_minify_recommendations&_wpnonce=' + nonce,
		callback: function(lightbox) {
			var theme = jQuery('#recom_theme').val();

			if (jQuery.ui && jQuery.ui.sortable) {
				jQuery("#recom_js_files,#recom_css_files").sortable({
					axis: 'y',
					stop: function() {
						jQuery(this).find('li').each(function(index) {
							jQuery(this).find('td:eq(1)').html((index + 1) + '.');
						});
					}
				});
			}

			if (w3tc_minify_recommendations_checked[theme] !== undefined) {
				jQuery('#recom_js_files :text,#recom_css_files :text').each(function() {
					var hash = jQuery(this).parents('li').find('[name=recom_js_template]').val() + ':' + jQuery(this).val();

					if (w3tc_minify_recommendations_checked[theme][hash] !== undefined) {
						var checkbox = jQuery(this).parents('li').find(':checkbox');

						if (w3tc_minify_recommendations_checked[theme][hash]) {
							checkbox.attr('checked', 'checked');
						} else {
							checkbox.removeAttr('checked');
						}
					}
				});
			}

			jQuery('#recom_theme').change(function() {
				jQuery('#recom_js_files :checkbox,#recom_css_files :checkbox').each(function() {
					var li = jQuery(this).parents('li');
					var hash = li.find('[name=recom_js_template]').val() + ':' + li.find(':text').val();

					if (w3tc_minify_recommendations_checked[theme] === undefined) {
						w3tc_minify_recommendations_checked[theme] = {};
					}

					w3tc_minify_recommendations_checked[theme][hash] = jQuery(this).is(':checked');
				});

				lightbox.load('admin.php?page=w3tc_minify&w3tc_test_minify_recommendations&theme_key=' + jQuery(this).val() + '&_wpnonce=' + nonce, lightbox.options.callback);
			});

			jQuery('#recom_js_check').on( 'click', function() {
				if (jQuery('#recom_js_files :checkbox:checked').length) {
					jQuery('#recom_js_files :checkbox').removeAttr('checked');
				} else {
					jQuery('#recom_js_files :checkbox').attr('checked', 'checked');
				}

				return false;
			});

			jQuery('#recom_css_check').on( 'click', function() {
				if (jQuery('#recom_css_files :checkbox:checked').length) {
					jQuery('#recom_css_files :checkbox').removeAttr('checked');
				} else {
					jQuery('#recom_css_files :checkbox').attr('checked', 'checked');
				}

				return false;
			});

			jQuery('.recom_apply', lightbox.container).on( 'click', function() {
				var theme = jQuery('#recom_theme').val();

				jQuery('#js_files li').each(function() {
					if (jQuery(this).find(':text').attr('name').indexOf('js_files[' + theme + ']') != -1) {
						jQuery(this).remove();
					}
				});

				jQuery('#css_files li').each(function() {
					if (jQuery(this).find(':text').attr('name').indexOf('css_files[' + theme + ']') != -1) {
						jQuery(this).remove();
					}
				});

				jQuery('#recom_js_files li').each(function() {
					if (jQuery(this).find(':checkbox:checked').length) {
						w3tc_minify_js_file_add(theme, jQuery(this).find('[name=recom_js_template]').val(), jQuery(this).find('[name=recom_js_location]').val(), jQuery(this).find('[name=recom_js_file]').val());
					}
				});

				jQuery('#recom_css_files li').each(function() {
					if (jQuery(this).find(':checkbox:checked').length) {
						w3tc_minify_css_file_add(theme, jQuery(this).find('[name=recom_css_template]').val(), jQuery(this).find('[name=recom_css_file]').val());
					}
				});

				w3tc_minify_js_theme(theme);
				w3tc_minify_css_theme(theme);

				w3tc_input_enable('.js_enabled', jQuery('#minify_js_enable:checked').length);
				w3tc_input_enable('.css_enabled', jQuery('#minify_css_enable:checked').length);

				lightbox.close();
			});
		}
	});
}

function w3tc_lightbox_self_test(nonce) {
	W3tc_Lightbox.open({
		width: 800,
		minHeight: 300,
		url: 'admin.php?page=w3tc_dashboard&w3tc_test_self&_wpnonce=' + w3tc_nonce,
		callback: function(lightbox) {
				jQuery('.button-primary', lightbox.container).on( 'click', function() {
				lightbox.close();
			});
		}
	});
}

function w3tc_lightbox_upgrade(nonce, data_src, renew_key) {
	var client_id = '';
	if (window.w3tc_ga) {
		w3tc_ga(function(tracker) {
			client_id = tracker.get('clientId');
		});
	}

  	W3tc_Lightbox.open({
		id: 'w3tc-overlay',
		close: '',
		width: 800,
		height: 350,
		url: 'admin.php?page=w3tc_dashboard&w3tc_licensing_upgrade&_wpnonce=' +
		encodeURIComponent(nonce) + '&data_src=' + encodeURIComponent(data_src) +
		(renew_key ? '&renew_key=' + encodeURIComponent(renew_key) : '') +
		(client_id ? '&client_id=' + encodeURIComponent(client_id) : ''),
	callback: function(lightbox) {
		lightbox.options.height = jQuery('#w3tc-upgrade').outerHeight();

		jQuery('.button-primary', lightbox.container).on( 'click', function() {
			lightbox.close();
		});
		jQuery('#w3tc-purchase', lightbox.container).on( 'click', function() {
			lightbox.close();
			w3tc_lightbox_buy_plugin(nonce, data_src, renew_key, client_id);
		});
		jQuery('#w3tc-purchase-link', lightbox.container).on( 'click', function() {
			lightbox.close();

			jQuery([document.documentElement, document.body]).animate({
				scrollTop: jQuery("#licensing").offset().top
			}, 2000);
		});

		// Allow for customizations of the "upgrade" overlay specifically.
		jQuery( '.w3tc-overlay' ).addClass( 'w3tc-overlay-upgrade' );

		lightbox.resize();
	}
  });
}

function w3tc_lightbox_buy_plugin(nonce, data_src, renew_key, client_id) {
	W3tc_Lightbox.open({
		width: 800,
		minHeight: 350,
		maxWidth: jQuery(window).width() - 40,
		maxHeight: jQuery(window).height() - 40,
		url: 'admin.php?page=w3tc_dashboard&w3tc_licensing_buy_plugin' +
			'&_wpnonce=' + encodeURIComponent(nonce) +
			'&data_src=' + encodeURIComponent(data_src) +
			(renew_key ? '&renew_key=' + encodeURIComponent(renew_key) : '') +
			(client_id ? '&client_id=' + encodeURIComponent(client_id) : ''),
		callback: function(lightbox) {
			var w3tc_license_listener = function(event) {
				if (event.origin.substr(event.origin.length - 12) !== ".w3-edge.com")
					return;

				var data = event.data.split(' ');
				if (data[0] === 'license') {
					// legacy purchase
					w3tc_lightbox_save_licence_key(function() {
						lightbox.close();
					});
				} else if (data[0] === 'v2_license') {
					// reset default timeout
					var iframe = document.getElementById('buy_frame');
					if (iframe.contentWindow && iframe.contentWindow.postMessage)
						iframe.contentWindow.postMessage('v2_license_accepted', '*');

					lightbox.options.onClose = function() {
						window.location = window.location + '&refresh';
					}

					w3tc_lightbox_save_licence_key(data[1], nonce, function() {
						jQuery('#buy_frame').attr('src', data[3]);
					});
				}
			}

			if (window.addEventListener) {
				addEventListener("message", w3tc_license_listener, false)
			} else if (attachEvent) {
				attachEvent("onmessage", w3tc_license_listener);
			}

			jQuery('.button-primary', lightbox.container).on( 'click', function() {
				lightbox.close();
			});
		}
	});
}

function w3tc_lightbox_save_licence_key(license_key, nonce, callback) {
  jQuery('#plugin_license_key').val(license_key);
  var params = {
	w3tc_default_save_licence_key: 1,
	license_key: license_key,
	_wpnonce: nonce
  };

  jQuery.post('admin.php?page=w3tc_dashboard', params, function(data) {
	callback();
  }, 'json').fail(callback);
}

jQuery(function() {
	jQuery('.button-minify-recommendations').on( 'click', function() {
		var nonce = jQuery(this).metadata().nonce;
		w3tc_lightbox_minify_recommendations(nonce);
		return false;
	});

	jQuery('.button-self-test').on( 'click', function() {
		var nonce = jQuery(this).metadata().nonce;
		w3tc_lightbox_self_test(nonce);
		return false;
	});

	jQuery('.button-buy-plugin').on( 'click', function() {
		var data_src = jQuery(this).data('src');
		var nonce = jQuery(this).data('nonce');
		if (!nonce) {
			nonce = w3tc_nonce;
		}
		var renew_key = jQuery(this).data('renew-key');

		w3tc_lightbox_upgrade(nonce, data_src, renew_key);
		jQuery('#w3tc-license-instruction').show();
		return false;
	});

	jQuery('body').on('click', '.w3tc_lightbox_close', function() {
		W3tc_Lightbox.close();
	});
});
