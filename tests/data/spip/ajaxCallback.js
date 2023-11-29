// A plugin that wraps all ajax calls introducing a fixed callback function on ajax complete
if(!jQuery.load_handlers) {
	jQuery.load_handlers = new Array();
	//
	// Add a function to the list of those to be executed on ajax load complete
	//
	function onAjaxLoad(f) {
		jQuery.load_handlers.push(f);
	};
	
	//
	// Call the functions that have been added to onAjaxLoad
	//
	function triggerAjaxLoad(root) {
    for ( var i = 0; i < jQuery.load_handlers.length; i++ )
			jQuery.load_handlers[i].apply( root );
	};

	// jQuery uses _load, we use _ACBload
	jQuery.fn._ACBload = jQuery.fn.load;
	
	jQuery.fn.load = function( url, params, callback ) {
	
		callback = callback || function(){};
	
		// If the second parameter was provided
		if ( params ) {
			// If it's a function
			if ( params.constructor == Function ) {
				// We assume that it's the callback
				callback = params;
				params = null;
			} 
		}
		var callback2 = function(res,status) {triggerAjaxLoad(this);callback(res,status);};
		
		return this._ACBload( url, params, callback2 );
	};

	jQuery._ACBajax = jQuery.ajax;
	
	jQuery.ajax = function(type) {
		//If called by _load exit now because the callback has already been set
		if (jQuery.ajax.caller==jQuery.fn._load) return jQuery._ACBajax( type);
			var orig_complete = type.complete || function() {};
			type.complete = function(res,status) {
				// Do not fire OnAjaxLoad if the dataType is not html
				var dataType = type.dataType;
				var ct = (res && (typeof res.getResponseHeader == 'function'))
					? res.getResponseHeader("content-type"): '';
				var xml = !dataType && ct && ct.indexOf("xml") >= 0;
				orig_complete(res,status);
				if(!dataType && !xml || dataType == "html") triggerAjaxLoad(document);
		};
		return jQuery._ACBajax(type);
	};

}

// animation du bloc cible pour faire patienter
jQuery.fn.animeajax = function(end) {
	this.children().css('opacity', 0.5);
	if (typeof ajax_image_searching != 'undefined'){
		var i = (this).find('.image_loading');
		if (i.length) i.html(ajax_image_searching);
		else this.prepend('<span class="image_loading">'+ajax_image_searching+'</span>');
	}
	return this; // don't break the chain
}

// s'il n'est pas totalement visible, scroller pour positionner
// le bloc cible en haut de l'ecran
jQuery.fn.positionner = function() {
	var offset = jQuery(this).offset({'scroll':false});
	var hauteur = parseInt(jQuery(this).css('height'));
	var scrolltop = self['pageYOffset'] ||
		jQuery.boxModel && document.documentElement[ 'scrollTop' ] ||
		document.body[ 'scrollTop' ];
	var h = jQuery(window).height();
	var scroll=0;

	if (offset['top'] - 5 <= scrolltop)
		scroll = offset['top'] - 5;
	else if (offset['top'] + hauteur - h + 5 > scrolltop)
		scroll = Math.min(offset['top'] - 5, offset['top'] + hauteur - h + 15);
	if (scroll)
		jQuery('html,body')
		.animate({scrollTop: scroll}, 300);

	// positionner le curseur dans la premiere zone de saisie
	jQuery(jQuery('*', this).filter('input[@type=text],textarea')[0]).focus();
	return this; // don't break the chain
}

// deux fonctions pour rendre l'ajax compatible Jaws
var virtualbuffer_id='spip_virtualbufferupdate';
function initReaderBuffer(){
	if (jQuery('#'+virtualbuffer_id).length) return;
	jQuery('body').append('<p style="float:left;width:0;height:0;position:absolute;left:-5000;top:-5000;"><input type="hidden" name="'+virtualbuffer_id+'" id="'+virtualbuffer_id+'" value="0" /></p>');
}
function updateReaderBuffer(){
	var i = jQuery('#'+virtualbuffer_id);
	if (!i.length) return;
	// incrementons l'input hidden, ce qui a pour effet de forcer le rafraichissement du 
	// buffer du lecteur d'ecran (au moins dans Jaws)
	i.attr('value',parseInt(i.attr('value'))+1);
}

// rechargement ajax d'un formulaire dynamique implemente par formulaires/xxx.html
jQuery.fn.formulaire_dyn_ajax = function(target) {
	if (this.length)
		initReaderBuffer();
  return this.each(function() {
	var cible = target || this;
		jQuery('form:not(.noajax)', this).each(function(){
		var leform = this;
		jQuery(this).prepend("<input type='hidden' name='var_ajax' value='form' />")
		.ajaxForm({
			beforeSubmit: function(){
				jQuery(cible).addClass('loading').animeajax();
			},
			success: function(c){
				if (c=='noajax'){
					// le serveur ne veut pas traiter ce formulaire en ajax
					// on resubmit sans ajax
					jQuery("input[@name=var_ajax]",leform).remove();
					jQuery(leform).ajaxFormUnbind().submit();
				}
				else {
					var d = jQuery('div.ajax',
						jQuery('<div><\/div>').html(c));
					if (d.length)
						c = d.html();
					jQuery(cible)
					.removeClass('loading')
					.html(c)
					.positionner()
					// on le refait a la main ici car onAjaxLoad intervient sur une iframe dans IE6 et non pas sur le document
					.formulaire_dyn_ajax();
					updateReaderBuffer();
				}
			},
			iframe: jQuery.browser.msie
		})
		.addClass('noajax') // previent qu'on n'ajaxera pas deux fois le meme formulaire en cas de ajaxload
		;
		});
  });
}

// permettre d'utiliser onclick='return confirm('etes vous sur?');' sur un lien ajax
var ajax_confirm=true;
var ajax_confirm_date=0;
var spip_confirm = window.confirm;
function _confirm(message){
	ajax_confirm = spip_confirm(message);
	if (!ajax_confirm) {
		var d = new Date();
		ajax_confirm_date = d.getTime();
	}
	return ajax_confirm;
}
window.confirm = _confirm;

// rechargement ajax d'une noisette implementee par {ajax}
// avec mise en cache des url
var preloaded_urls = {};
var ajaxbloc_selecteur;
jQuery.fn.ajaxbloc = function() {
	if (this.length)
		initReaderBuffer();
  return this.each(function() {
  jQuery('div.ajaxbloc',this).ajaxbloc(); // traiter les enfants d'abord
	var blocfrag = jQuery(this);
	
	var on_pagination = function(c) {
		jQuery(blocfrag)
		.html(c)
		.removeClass('loading')
		.positionner();
		updateReaderBuffer();
	}

	var ajax_env = (""+blocfrag.attr('class')).match(/env-([^ ]+)/);
	if (!ajax_env || ajax_env==undefined) return;
	ajax_env = ajax_env[1];
	if (ajaxbloc_selecteur==undefined)
		ajaxbloc_selecteur = '.pagination a,a.ajax';
	jQuery(ajaxbloc_selecteur,this).not('.noajax').each(function(){
		var url = this.href.split('#');
		url[0] += (url[0].indexOf("?")>0 ? '&':'?')+'var_ajax=1&var_ajax_env='+encodeURIComponent(ajax_env);
		if (jQuery(this).is('.preload') && !preloaded_urls[url[0]]) {
			jQuery.ajax({"url":url[0],"success":function(r){preloaded_urls[url[0]]=r;}});
		}
		jQuery(this).click(function(){
			if (!ajax_confirm) {
				// on rearme pour le prochain clic
				ajax_confirm=true;
				var d = new Date();
				// seule une annulation par confirm() dans les 2 secondes precedentes est prise en compte
				if ((d.getTime()-ajax_confirm_date)<=2)
					return false;
			}
			jQuery(blocfrag)
			.animeajax()
			.addClass('loading');
			if (preloaded_urls[url[0]]) {
				on_pagination(preloaded_urls[url[0]]);
				triggerAjaxLoad(document);
			} else {
				jQuery.ajax({
					url: url[0],
					success: function(c){
						on_pagination(c);
						preloaded_urls[url[0]] = c;
					}
				});
			}
			return false;
		});
	}).addClass('noajax'); // previent qu'on ajax pas deux fois le meme lien
  });
};

// Ajaxer les formulaires qui le demandent, au demarrage

jQuery(function() {
	jQuery('form').parents('div.ajax')
	.formulaire_dyn_ajax();
	jQuery('div.ajaxbloc').ajaxbloc();
});

// ... et a chaque fois que le DOM change
onAjaxLoad(function() {
	if (jQuery){
		jQuery('form', this).parents('div.ajax')
		.formulaire_dyn_ajax();
		jQuery('div.ajaxbloc', this)
		.ajaxbloc();
	}
});