(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/*
object-assign
(c) Sindre Sorhus
@license MIT
*/

'use strict';

/* eslint-disable no-unused-vars */
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var propIsEnumerable = Object.prototype.propertyIsEnumerable;
function toObject(val) {
  if (val === null || val === undefined) {
    throw new TypeError('Object.assign cannot be called with null or undefined');
  }
  return Object(val);
}
function shouldUseNative() {
  try {
    if (!Object.assign) {
      return false;
    }

    // Detect buggy property enumeration order in older V8 versions.

    // https://bugs.chromium.org/p/v8/issues/detail?id=4118
    var test1 = new String('abc'); // eslint-disable-line no-new-wrappers
    test1[5] = 'de';
    if (Object.getOwnPropertyNames(test1)[0] === '5') {
      return false;
    }

    // https://bugs.chromium.org/p/v8/issues/detail?id=3056
    var test2 = {};
    for (var i = 0; i < 10; i++) {
      test2['_' + String.fromCharCode(i)] = i;
    }
    var order2 = Object.getOwnPropertyNames(test2).map(function (n) {
      return test2[n];
    });
    if (order2.join('') !== '0123456789') {
      return false;
    }

    // https://bugs.chromium.org/p/v8/issues/detail?id=3056
    var test3 = {};
    'abcdefghijklmnopqrst'.split('').forEach(function (letter) {
      test3[letter] = letter;
    });
    if (Object.keys(Object.assign({}, test3)).join('') !== 'abcdefghijklmnopqrst') {
      return false;
    }
    return true;
  } catch (err) {
    // We don't expect any of the above to throw, but better to be safe.
    return false;
  }
}
module.exports = shouldUseNative() ? Object.assign : function (target, source) {
  var from;
  var to = toObject(target);
  var symbols;
  for (var s = 1; s < arguments.length; s++) {
    from = Object(arguments[s]);
    for (var key in from) {
      if (hasOwnProperty.call(from, key)) {
        to[key] = from[key];
      }
    }
    if (getOwnPropertySymbols) {
      symbols = getOwnPropertySymbols(from);
      for (var i = 0; i < symbols.length; i++) {
        if (propIsEnumerable.call(from, symbols[i])) {
          to[symbols[i]] = from[symbols[i]];
        }
      }
    }
  }
  return to;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJnZXRPd25Qcm9wZXJ0eVN5bWJvbHMiLCJPYmplY3QiLCJoYXNPd25Qcm9wZXJ0eSIsInByb3RvdHlwZSIsInByb3BJc0VudW1lcmFibGUiLCJwcm9wZXJ0eUlzRW51bWVyYWJsZSIsInRvT2JqZWN0IiwidmFsIiwidW5kZWZpbmVkIiwiVHlwZUVycm9yIiwic2hvdWxkVXNlTmF0aXZlIiwiYXNzaWduIiwidGVzdDEiLCJTdHJpbmciLCJnZXRPd25Qcm9wZXJ0eU5hbWVzIiwidGVzdDIiLCJpIiwiZnJvbUNoYXJDb2RlIiwib3JkZXIyIiwibWFwIiwibiIsImpvaW4iLCJ0ZXN0MyIsInNwbGl0IiwiZm9yRWFjaCIsImxldHRlciIsImtleXMiLCJlcnIiLCJtb2R1bGUiLCJleHBvcnRzIiwidGFyZ2V0Iiwic291cmNlIiwiZnJvbSIsInRvIiwic3ltYm9scyIsInMiLCJhcmd1bWVudHMiLCJsZW5ndGgiLCJrZXkiLCJjYWxsIl0sInNvdXJjZXMiOlsiaW5kZXguanMiXSwic291cmNlc0NvbnRlbnQiOlsiLypcbm9iamVjdC1hc3NpZ25cbihjKSBTaW5kcmUgU29yaHVzXG5AbGljZW5zZSBNSVRcbiovXG5cbid1c2Ugc3RyaWN0Jztcbi8qIGVzbGludC1kaXNhYmxlIG5vLXVudXNlZC12YXJzICovXG52YXIgZ2V0T3duUHJvcGVydHlTeW1ib2xzID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scztcbnZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG52YXIgcHJvcElzRW51bWVyYWJsZSA9IE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGU7XG5cbmZ1bmN0aW9uIHRvT2JqZWN0KHZhbCkge1xuXHRpZiAodmFsID09PSBudWxsIHx8IHZhbCA9PT0gdW5kZWZpbmVkKSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignT2JqZWN0LmFzc2lnbiBjYW5ub3QgYmUgY2FsbGVkIHdpdGggbnVsbCBvciB1bmRlZmluZWQnKTtcblx0fVxuXG5cdHJldHVybiBPYmplY3QodmFsKTtcbn1cblxuZnVuY3Rpb24gc2hvdWxkVXNlTmF0aXZlKCkge1xuXHR0cnkge1xuXHRcdGlmICghT2JqZWN0LmFzc2lnbikge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdC8vIERldGVjdCBidWdneSBwcm9wZXJ0eSBlbnVtZXJhdGlvbiBvcmRlciBpbiBvbGRlciBWOCB2ZXJzaW9ucy5cblxuXHRcdC8vIGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTQxMThcblx0XHR2YXIgdGVzdDEgPSBuZXcgU3RyaW5nKCdhYmMnKTsgIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3LXdyYXBwZXJzXG5cdFx0dGVzdDFbNV0gPSAnZGUnO1xuXHRcdGlmIChPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0ZXN0MSlbMF0gPT09ICc1Jykge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdC8vIGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTMwNTZcblx0XHR2YXIgdGVzdDIgPSB7fTtcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IDEwOyBpKyspIHtcblx0XHRcdHRlc3QyWydfJyArIFN0cmluZy5mcm9tQ2hhckNvZGUoaSldID0gaTtcblx0XHR9XG5cdFx0dmFyIG9yZGVyMiA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRlc3QyKS5tYXAoZnVuY3Rpb24gKG4pIHtcblx0XHRcdHJldHVybiB0ZXN0MltuXTtcblx0XHR9KTtcblx0XHRpZiAob3JkZXIyLmpvaW4oJycpICE9PSAnMDEyMzQ1Njc4OScpIHtcblx0XHRcdHJldHVybiBmYWxzZTtcblx0XHR9XG5cblx0XHQvLyBodHRwczovL2J1Z3MuY2hyb21pdW0ub3JnL3AvdjgvaXNzdWVzL2RldGFpbD9pZD0zMDU2XG5cdFx0dmFyIHRlc3QzID0ge307XG5cdFx0J2FiY2RlZmdoaWprbG1ub3BxcnN0Jy5zcGxpdCgnJykuZm9yRWFjaChmdW5jdGlvbiAobGV0dGVyKSB7XG5cdFx0XHR0ZXN0M1tsZXR0ZXJdID0gbGV0dGVyO1xuXHRcdH0pO1xuXHRcdGlmIChPYmplY3Qua2V5cyhPYmplY3QuYXNzaWduKHt9LCB0ZXN0MykpLmpvaW4oJycpICE9PVxuXHRcdFx0XHQnYWJjZGVmZ2hpamtsbW5vcHFyc3QnKSB7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHRydWU7XG5cdH0gY2F0Y2ggKGVycikge1xuXHRcdC8vIFdlIGRvbid0IGV4cGVjdCBhbnkgb2YgdGhlIGFib3ZlIHRvIHRocm93LCBidXQgYmV0dGVyIHRvIGJlIHNhZmUuXG5cdFx0cmV0dXJuIGZhbHNlO1xuXHR9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gc2hvdWxkVXNlTmF0aXZlKCkgPyBPYmplY3QuYXNzaWduIDogZnVuY3Rpb24gKHRhcmdldCwgc291cmNlKSB7XG5cdHZhciBmcm9tO1xuXHR2YXIgdG8gPSB0b09iamVjdCh0YXJnZXQpO1xuXHR2YXIgc3ltYm9scztcblxuXHRmb3IgKHZhciBzID0gMTsgcyA8IGFyZ3VtZW50cy5sZW5ndGg7IHMrKykge1xuXHRcdGZyb20gPSBPYmplY3QoYXJndW1lbnRzW3NdKTtcblxuXHRcdGZvciAodmFyIGtleSBpbiBmcm9tKSB7XG5cdFx0XHRpZiAoaGFzT3duUHJvcGVydHkuY2FsbChmcm9tLCBrZXkpKSB7XG5cdFx0XHRcdHRvW2tleV0gPSBmcm9tW2tleV07XG5cdFx0XHR9XG5cdFx0fVxuXG5cdFx0aWYgKGdldE93blByb3BlcnR5U3ltYm9scykge1xuXHRcdFx0c3ltYm9scyA9IGdldE93blByb3BlcnR5U3ltYm9scyhmcm9tKTtcblx0XHRcdGZvciAodmFyIGkgPSAwOyBpIDwgc3ltYm9scy5sZW5ndGg7IGkrKykge1xuXHRcdFx0XHRpZiAocHJvcElzRW51bWVyYWJsZS5jYWxsKGZyb20sIHN5bWJvbHNbaV0pKSB7XG5cdFx0XHRcdFx0dG9bc3ltYm9sc1tpXV0gPSBmcm9tW3N5bWJvbHNbaV1dO1xuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0fVxuXHR9XG5cblx0cmV0dXJuIHRvO1xufTtcbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxZQUFZOztBQUNaO0FBQ0EsSUFBSUEscUJBQXFCLEdBQUdDLE1BQU0sQ0FBQ0QscUJBQXFCO0FBQ3hELElBQUlFLGNBQWMsR0FBR0QsTUFBTSxDQUFDRSxTQUFTLENBQUNELGNBQWM7QUFDcEQsSUFBSUUsZ0JBQWdCLEdBQUdILE1BQU0sQ0FBQ0UsU0FBUyxDQUFDRSxvQkFBb0I7QUFFNUQsU0FBU0MsUUFBUSxDQUFDQyxHQUFHLEVBQUU7RUFDdEIsSUFBSUEsR0FBRyxLQUFLLElBQUksSUFBSUEsR0FBRyxLQUFLQyxTQUFTLEVBQUU7SUFDdEMsTUFBTSxJQUFJQyxTQUFTLENBQUMsdURBQXVELENBQUM7RUFDN0U7RUFFQSxPQUFPUixNQUFNLENBQUNNLEdBQUcsQ0FBQztBQUNuQjtBQUVBLFNBQVNHLGVBQWUsR0FBRztFQUMxQixJQUFJO0lBQ0gsSUFBSSxDQUFDVCxNQUFNLENBQUNVLE1BQU0sRUFBRTtNQUNuQixPQUFPLEtBQUs7SUFDYjs7SUFFQTs7SUFFQTtJQUNBLElBQUlDLEtBQUssR0FBRyxJQUFJQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBRTtJQUNoQ0QsS0FBSyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUk7SUFDZixJQUFJWCxNQUFNLENBQUNhLG1CQUFtQixDQUFDRixLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsS0FBSyxHQUFHLEVBQUU7TUFDakQsT0FBTyxLQUFLO0lBQ2I7O0lBRUE7SUFDQSxJQUFJRyxLQUFLLEdBQUcsQ0FBQyxDQUFDO0lBQ2QsS0FBSyxJQUFJQyxDQUFDLEdBQUcsQ0FBQyxFQUFFQSxDQUFDLEdBQUcsRUFBRSxFQUFFQSxDQUFDLEVBQUUsRUFBRTtNQUM1QkQsS0FBSyxDQUFDLEdBQUcs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
},{}],2:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};
process.nextTick = function () {
  var canSetImmediate = typeof window !== 'undefined' && window.setImmediate;
  var canPost = typeof window !== 'undefined' && window.postMessage && window.addEventListener;
  if (canSetImmediate) {
    return function (f) {
      return window.setImmediate(f);
    };
  }
  if (canPost) {
    var queue = [];
    window.addEventListener('message', function (ev) {
      var source = ev.source;
      if ((source === window || source === null) && ev.data === 'process-tick') {
        ev.stopPropagation();
        if (queue.length > 0) {
          var fn = queue.shift();
          fn();
        }
      }
    }, true);
    return function nextTick(fn) {
      queue.push(fn);
      window.postMessage('process-tick', '*');
    };
  }
  return function nextTick(fn) {
    setTimeout(fn, 0);
  };
}();
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
function noop() {}
process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.binding = function (name) {
  throw new Error('process.binding is not supported');
};

// TODO(shtylman)
process.cwd = function () {
  return '/';
};
process.chdir = function (dir) {
  throw new Error('process.chdir is not supported');
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwibW9kdWxlIiwiZXhwb3J0cyIsIm5leHRUaWNrIiwiY2FuU2V0SW1tZWRpYXRlIiwid2luZG93Iiwic2V0SW1tZWRpYXRlIiwiY2FuUG9zdCIsInBvc3RNZXNzYWdlIiwiYWRkRXZlbnRMaXN0ZW5lciIsImYiLCJxdWV1ZSIsImV2Iiwic291cmNlIiwiZGF0YSIsInN0b3BQcm9wYWdhdGlvbiIsImxlbmd0aCIsImZuIiwic2hpZnQiLCJwdXNoIiwic2V0VGltZW91dCIsInRpdGxlIiwiYnJvd3NlciIsImVudiIsImFyZ3YiLCJub29wIiwib24iLCJhZGRMaXN0ZW5lciIsIm9uY2UiLCJvZmYiLCJyZW1vdmVMaXN0ZW5lciIsInJlbW92ZUFsbExpc3RlbmVycyIsImVtaXQiLCJiaW5kaW5nIiwibmFtZSIsIkVycm9yIiwiY3dkIiwiY2hkaXIiLCJkaXIiXSwic291cmNlcyI6WyJicm93c2VyLmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8vIHNoaW0gZm9yIHVzaW5nIHByb2Nlc3MgaW4gYnJvd3NlclxuXG52YXIgcHJvY2VzcyA9IG1vZHVsZS5leHBvcnRzID0ge307XG5cbnByb2Nlc3MubmV4dFRpY2sgPSAoZnVuY3Rpb24gKCkge1xuICAgIHZhciBjYW5TZXRJbW1lZGlhdGUgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJ1xuICAgICYmIHdpbmRvdy5zZXRJbW1lZGlhdGU7XG4gICAgdmFyIGNhblBvc3QgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJ1xuICAgICYmIHdpbmRvdy5wb3N0TWVzc2FnZSAmJiB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lclxuICAgIDtcblxuICAgIGlmIChjYW5TZXRJbW1lZGlhdGUpIHtcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChmKSB7IHJldHVybiB3aW5kb3cuc2V0SW1tZWRpYXRlKGYpIH07XG4gICAgfVxuXG4gICAgaWYgKGNhblBvc3QpIHtcbiAgICAgICAgdmFyIHF1ZXVlID0gW107XG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgZnVuY3Rpb24gKGV2KSB7XG4gICAgICAgICAgICB2YXIgc291cmNlID0gZXYuc291cmNlO1xuICAgICAgICAgICAgaWYgKChzb3VyY2UgPT09IHdpbmRvdyB8fCBzb3VyY2UgPT09IG51bGwpICYmIGV2LmRhdGEgPT09ICdwcm9jZXNzLXRpY2snKSB7XG4gICAgICAgICAgICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG4gICAgICAgICAgICAgICAgaWYgKHF1ZXVlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZuID0gcXVldWUuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgZm4oKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0sIHRydWUpO1xuXG4gICAgICAgIHJldHVybiBmdW5jdGlvbiBuZXh0VGljayhmbikge1xuICAgICAgICAgICAgcXVldWUucHVzaChmbik7XG4gICAgICAgICAgICB3aW5kb3cucG9zdE1lc3NhZ2UoJ3Byb2Nlc3MtdGljaycsICcqJyk7XG4gICAgICAgIH07XG4gICAgfVxuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIG5leHRUaWNrKGZuKSB7XG4gICAgICAgIHNldFRpbWVvdXQoZm4sIDApO1xuICAgIH07XG59KSgpO1xuXG5wcm9jZXNzLnRpdGxlID0gJ2Jyb3dzZXInO1xucHJvY2Vzcy5icm93c2VyID0gdHJ1ZTtcbnByb2Nlc3MuZW52ID0ge307XG5wcm9jZXNzLmFyZ3YgPSBbXTtcblxuZnVuY3Rpb24gbm9vcCgpIHt9XG5cbnByb2Nlc3Mub24gPSBub29wO1xucHJvY2Vzcy5hZGRMaXN0ZW5lciA9IG5vb3A7XG5wcm9jZXNzLm9uY2UgPSBub29wO1xucHJvY2Vzcy5vZmYgPSBub29wO1xucHJvY2Vzcy5yZW1vdmVMaXN0ZW5lciA9IG5vb3A7XG5wcm9jZXNzLnJlbW92ZUFsbExpc3RlbmVycyA9IG5vb3A7XG5wcm9jZXNzLmVtaXQgPSBub29wO1xuXG5wcm9jZXNzLmJpbmRpbmcgPSBmdW5jdGlvbiAobmFtZSkge1xuICAgIHRocm93IG5ldyBFcnJvcigncHJvY2Vzcy5iaW5kaW5nIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbn1cblxuLy8gVE9ETyhzaHR5bG1hbilcbnByb2Nlc3MuY3dkID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gJy8nIH07XG5wcm9jZXNzLmNoZGlyID0gZnVuY3Rpb24gKGRpcikge1xuICAgIHRocm93IG5ldyBFcnJvcigncHJvY2Vzcy5jaGRpciBpcyBub3Qgc3VwcG9ydGVkJyk7XG59O1xuIl0sIm1hcHBpbmdzIjoiQUFBQTs7QUFFQSxJQUFJQSxPQUFPLEdBQUdDLE1BQU0sQ0FBQ0MsT0FBTyxHQUFHLENBQUMsQ0FBQztBQUVqQ0YsT0FBTyxDQUFDRyxRQUFRLEdBQUksWUFBWTtFQUM1QixJQUFJQyxlQUFlLEdBQUcsT0FBT0MsTUFBTSxLQUFLLFdBQVcsSUFDaERBLE1BQU0sQ0FBQ0MsWUFBWTtFQUN0QixJQUFJQyxPQUFPLEdBQUcsT0FBT0YsTUFBTSxLQUFLLFdBQVcsSUFDeENBLE1BQU0sQ0FBQ0csV0FBVyxJQUFJSCxNQUFNLENBQUNJLGdCQUFnQjtFQUdoRCxJQUFJTCxlQUFlLEVBQUU7SUFDakIsT0FBTyxVQUFVTSxDQUFDLEVBQUU7TUFBRSxPQUFPTCxNQUFNLENBQUNDLFlBQVksQ0FBQ0ksQ0FBQyxDQUFDO0lBQUMsQ0FBQztFQUN6RDtFQUVBLElBQUlILE9BQU8sRUFBRTtJQUNULElBQUlJLEtBQUssR0FBRyxFQUFFO0lBQ2ROLE1BQU0sQ0FBQ0ksZ0JBQWdCLENBQUMsU0FBUyxFQUFFLFVBQVVHLEVBQUUsRUFBRTtNQUM3QyxJQUFJQyxNQUFNLEdBQUdELEVBQUUsQ0FBQ0MsTUFBTTtNQUN0QixJQUFJLENBQUNBLE1BQU0sS0FBS1IsTUFBTSxJQUFJUSxNQUFNLEtBQUssSUFBSSxLQUFLRCxFQUFFLENBQUNFLElBQUksS0FBSyxjQUFjLEVBQUU7UUFDdEVGLEVBQUUsQ0FBQ0csZUFBZSxFQUFFO1FBQ3BCLElBQUlKLEtBQUssQ0FBQ0ssTUFBTSxHQUFHLENBQUMsRUFBRTtVQUNsQixJQUFJQyxFQUFFLEdBQUdOLEtBQUssQ0FBQ08sS0FBSyxFQUFFO1VBQ3RCRCxFQUFFLEVBQUU7UUFDUjtNQUNKO0lBQ0osQ0FBQyxFQUFFLElBQUksQ0FBQztJQUVSLE9BQU8sU0FBU2QsUUFBUSxDQUFDYyxFQUFFLEVBQUU7TUFDekJOLEtBQUssQ0FBQ1EsSUFBSSxDQUFDRixFQUFFLENBQUM7TUFDZFosTUFBTSxDQUFDRyxXQUFXLENBQUMsY0FBYyxFQUFFLEdBQUcsQ0FBQztJQUMzQyxDQUFDO0VBQ0w7RUFFQSxPQUFPLFNBQVNMLFFBQVEsQ0FBQ2MsRUFBRSxFQUFFO0lBQ3pCRyxVQUFVLENBQUNILEVBQUUsRUFBRSxDQUFDLENBQUM7RUFDckIsQ0FBQztBQUNMLENBQUMsRUFBRztBQUVKakIsT0FBTyxDQUFDcUIsS0FBSyxHQUFHLFNBQVM7QUFDekJyQixPQUFPLENBQUNzQixPQUFPLEdBQUcsSUFBSTtBQUN0QnRCLE9BQU8sQ0FBQ3VCLEdBQUcsR0FBRyxDQUFDLENBQUM7QUFDaEJ2QixPQUFPLENBQUN3QixJQUFJLEdBQUcsRUFBRTtBQUVqQixTQUFTQyxJQUFJLEdBQUcsQ0FBQztBQUVqQnpCLE9BQU8sQ0FBQzBCLEVBQUUsR0FBR0QsSUFBSTtBQUNqQnpCLE9BQU8sQ0FBQzJCLFdBQVcsR0FBR0YsSUFBSTtBQUMxQnpCLE9BQU8sQ0FBQzRCLElBQUksR0FBR0gsSUFBSTtBQUNuQnpCLE9BQU8sQ0FBQzZCLEdBQUcsR0FBR0osSUFBSTtBQUNsQnpCLE9BQU8sQ0FBQzhCLGNBQWMsR0FBR0wsSUFBSTtBQUM3QnpCLE9BQU8sQ0FBQytCLGtCQUFrQixHQUFHTixJQUFJO0FBQ2pDekIsT0FBTyxDQUFDZ0MsSUFBSSxHQUFHUCxJQUFJO0FBRW5CekIsT0FBTyxDQUFDaUMsT0FBTyxHQUFHLFVBQVVDLElBQUksRUFBRTtFQUM5QixNQUFNLElBQUlDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQztBQUN2RCxDQUFDOztBQUVEO0FBQ0FuQyxPQUFPLENBQUNvQyxHQUFHLEdBQUcsWUFBWTtFQUFFLE9BQU8sR0FBRztBQUFDLENBQUM7QUFDeENwQyxPQUFPLENBQUNxQyxLQUFLLEdBQUcsVUFBVUMsR0FBRyxFQUFFO0VBQzNCLE1BQU0sSUFBSUgsS0FBSyxDQUFDLGdDQUFnQyxDQUFDO0FBQ3JELENBQUMifQ==
},{}],3:[function(require,module,exports){
(function (process){
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var printWarning = function () {};
if (process.env.NODE_ENV !== 'production') {
  var ReactPropTypesSecret = require('./lib/ReactPropTypesSecret');
  var loggedTypeFailures = {};
  var has = require('./lib/has');
  printWarning = function (text) {
    var message = 'Warning: ' + text;
    if (typeof console !== 'undefined') {
      console.error(message);
    }
    try {
      // --- Welcome to debugging React ---
      // This error was thrown as a convenience so that you can use this stack
      // to find the callsite that caused this warning to fire.
      throw new Error(message);
    } catch (x) {/**/}
  };
}

/**
 * Assert that the values match with the type specs.
 * Error messages are memorized and will only be shown once.
 *
 * @param {object} typeSpecs Map of name to a ReactPropType
 * @param {object} values Runtime values that need to be type-checked
 * @param {string} location e.g. "prop", "context", "child context"
 * @param {string} componentName Name of the component for error messages.
 * @param {?Function} getStack Returns the component stack.
 * @private
 */
function checkPropTypes(typeSpecs, values, location, componentName, getStack) {
  if (process.env.NODE_ENV !== 'production') {
    for (var typeSpecName in typeSpecs) {
      if (has(typeSpecs, typeSpecName)) {
        var error;
        // Prop type validation may throw. In case they do, we don't want to
        // fail the render phase where it didn't fail before. So we log it.
        // After these have been cleaned up, we'll let them throw.
        try {
          // This is intentionally an invariant that gets caught. It's the same
          // behavior as without this statement except with a better message.
          if (typeof typeSpecs[typeSpecName] !== 'function') {
            var err = Error((componentName || 'React class') + ': ' + location + ' type `' + typeSpecName + '` is invalid; ' + 'it must be a function, usually from the `prop-types` package, but received `' + typeof typeSpecs[typeSpecName] + '`.' + 'This often happens because of typos such as `PropTypes.function` instead of `PropTypes.func`.');
            err.name = 'Invariant Violation';
            throw err;
          }
          error = typeSpecs[typeSpecName](values, typeSpecName, componentName, location, null, ReactPropTypesSecret);
        } catch (ex) {
          error = ex;
        }
        if (error && !(error instanceof Error)) {
          printWarning((componentName || 'React class') + ': type specification of ' + location + ' `' + typeSpecName + '` is invalid; the type checker ' + 'function must return `null` or an `Error` but returned a ' + typeof error + '. ' + 'You may have forgotten to pass an argument to the type checker ' + 'creator (arrayOf, instanceOf, objectOf, oneOf, oneOfType, and ' + 'shape all require an argument).');
        }
        if (error instanceof Error && !(error.message in loggedTypeFailures)) {
          // Only monitor this failure once because there tends to be a lot of the
          // same error.
          loggedTypeFailures[error.message] = true;
          var stack = getStack ? getStack() : '';
          printWarning('Failed ' + location + ' type: ' + error.message + (stack != null ? stack : ''));
        }
      }
    }
  }
}

/**
 * Resets warning cache when testing.
 *
 * @private
 */
checkPropTypes.resetWarningCache = function () {
  if (process.env.NODE_ENV !== 'production') {
    loggedTypeFailures = {};
  }
};
module.exports = checkPropTypes;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcmludFdhcm5pbmciLCJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJSZWFjdFByb3BUeXBlc1NlY3JldCIsInJlcXVpcmUiLCJsb2dnZWRUeXBlRmFpbHVyZXMiLCJoYXMiLCJ0ZXh0IiwibWVzc2FnZSIsImNvbnNvbGUiLCJlcnJvciIsIkVycm9yIiwieCIsImNoZWNrUHJvcFR5cGVzIiwidHlwZVNwZWNzIiwidmFsdWVzIiwibG9jYXRpb24iLCJjb21wb25lbnROYW1lIiwiZ2V0U3RhY2siLCJ0eXBlU3BlY05hbWUiLCJlcnIiLCJuYW1lIiwiZXgiLCJzdGFjayIsInJlc2V0V2FybmluZ0NhY2hlIiwibW9kdWxlIiwiZXhwb3J0cyJdLCJzb3VyY2VzIjpbImNoZWNrUHJvcFR5cGVzLmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQ29weXJpZ2h0IChjKSAyMDEzLXByZXNlbnQsIEZhY2Vib29rLCBJbmMuXG4gKlxuICogVGhpcyBzb3VyY2UgY29kZSBpcyBsaWNlbnNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2UgZm91bmQgaW4gdGhlXG4gKiBMSUNFTlNFIGZpbGUgaW4gdGhlIHJvb3QgZGlyZWN0b3J5IG9mIHRoaXMgc291cmNlIHRyZWUuXG4gKi9cblxuJ3VzZSBzdHJpY3QnO1xuXG52YXIgcHJpbnRXYXJuaW5nID0gZnVuY3Rpb24oKSB7fTtcblxuaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicpIHtcbiAgdmFyIFJlYWN0UHJvcFR5cGVzU2VjcmV0ID0gcmVxdWlyZSgnLi9saWIvUmVhY3RQcm9wVHlwZXNTZWNyZXQnKTtcbiAgdmFyIGxvZ2dlZFR5cGVGYWlsdXJlcyA9IHt9O1xuICB2YXIgaGFzID0gcmVxdWlyZSgnLi9saWIvaGFzJyk7XG5cbiAgcHJpbnRXYXJuaW5nID0gZnVuY3Rpb24odGV4dCkge1xuICAgIHZhciBtZXNzYWdlID0gJ1dhcm5pbmc6ICcgKyB0ZXh0O1xuICAgIGlmICh0eXBlb2YgY29uc29sZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAvLyAtLS0gV2VsY29tZSB0byBkZWJ1Z2dpbmcgUmVhY3QgLS0tXG4gICAgICAvLyBUaGlzIGVycm9yIHdhcyB0aHJvd24gYXMgYSBjb252ZW5pZW5jZSBzbyB0aGF0IHlvdSBjYW4gdXNlIHRoaXMgc3RhY2tcbiAgICAgIC8vIHRvIGZpbmQgdGhlIGNhbGxzaXRlIHRoYXQgY2F1c2VkIHRoaXMgd2FybmluZyB0byBmaXJlLlxuICAgICAgdGhyb3cgbmV3IEVycm9yKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKHgpIHsgLyoqLyB9XG4gIH07XG59XG5cbi8qKlxuICogQXNzZXJ0IHRoYXQgdGhlIHZhbHVlcyBtYXRjaCB3aXRoIHRoZSB0eXBlIHNwZWNzLlxuICogRXJyb3IgbWVzc2FnZXMgYXJlIG1lbW9yaXplZCBhbmQgd2lsbCBvbmx5IGJlIHNob3duIG9uY2UuXG4gKlxuICogQHBhcmFtIHtvYmplY3R9IHR5cGVTcGVjcyBNYXAgb2YgbmFtZSB0byBhIFJlYWN0UHJvcFR5cGVcbiAqIEBwYXJhbSB7b2JqZWN0fSB2YWx1ZXMgUnVudGltZSB2YWx1ZXMgdGhhdCBuZWVkIHRvIGJlIHR5cGUtY2hlY2tlZFxuICogQHBhcmFtIHtzdHJpbmd9IGxvY2F0aW9uIGUuZy4gXCJwcm9wXCIsIFwiY29udGV4dFwiLCBcImNoaWxkIGNvbnRleHRcIlxuICogQHBhcmFtIHtzdHJpbmd9IGNvbXBvbmVudE5hbWUgTmFtZSBvZiB0aGUgY29tcG9uZW50IGZvciBlcnJvciBtZXNzYWdlcy5cbiAqIEBwYXJhbSB7P0Z1bmN0aW9ufSBnZXRTdGFjayBSZXR1cm5zIHRoZSBjb21wb25lbnQgc3RhY2suXG4gKiBAcHJpdmF0ZVxuICovXG5mdW5jdGlvbiBjaGVja1Byb3BUeXBlcyh0eXBlU3BlY3MsIHZhbHVlcywgbG9jYXRpb24sIGNvbXBvbmVudE5hbWUsIGdldFN0YWNrKSB7XG4gIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG4gICAgZm9yICh2YXIgdHlwZVNwZWNOYW1lIGluIHR5cGVTcGVjcykge1xuICAgICAgaWYgKGhhcyh0eXBlU3BlY3MsIHR5cGVTcGVjTmFtZSkpIHtcbiAgICAgICAgdmFyIGVycm9yO1xuICAgICAgICAvLyBQcm9wIHR5cGUgdmFsaWRhdGlvbiBtYXkgdGhyb3cuIEluIGNhc2UgdGhleSBkbywgd2UgZG9uJ3Qgd2FudCB0b1xuICAgICAgICAvLyBmYWlsIHRoZSByZW5kZXIgcGhhc2Ugd2hlcmUgaXQgZGlkbid0IGZhaWwgYmVmb3JlLiBTbyB3ZSBsb2cgaXQuXG4gICAgICAgIC8vIEFmdGVyIHRoZXNlIGhhdmUgYmVlbiBjbGVhbmVkIHVwLCB3ZSdsbCBsZXQgdGhlbSB0aHJvdy5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAvLyBUaGlzIGlzIGludGVudGlvbmFsbHkgYW4gaW52YXJpYW50IHRoYXQgZ2V0cyBjYXVnaHQuIEl0J3MgdGhlIHNhbWVcbiAgICAgICAgICAvLyBiZWhhdmlvciBhcyB3aXRob3V0IHRoaXMgc3RhdGVtZW50IGV4Y2VwdCB3aXRoIGEgYmV0dGVyIG1lc3NhZ2UuXG4gICAgICAgICAgaWYgKHR5cGVvZiB0eXBlU3BlY3NbdHlwZVNwZWNOYW1lXSAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgdmFyIGVyciA9IEVycm9yKFxuICAgICAgICAgICAgICAoY29tcG9uZW50TmFtZSB8fCAnUmVhY3QgY2xhc3MnKSArICc6ICcgKyBsb2NhdGlvbiArICcgdHlwZSBgJyArIHR5cGVTcGVjTmFtZSArICdgIGlzIGludmFsaWQ7ICcgK1xuICAgICAgICAgICAgICAnaXQgbXVzdCBiZSBhIGZ1bmN0aW9uLCB1c3VhbGx5IGZyb20gdGhlIGBwcm9wLXR5cGVzYCBwYWNrYWdlLCBidXQgcmVjZWl2ZWQgYCcgKyB0eXBlb2YgdHlwZVNwZWNzW3R5cGVTcGVjTmFtZV0gKyAnYC4nICtcbiAgICAgICAgICAgICAgJ1RoaXMgb2Z0ZW4gaGFwcGVucyBiZWNhdXNlIG9mIHR5cG9zIHN1Y2ggYXMgYFByb3BUeXBlcy5mdW5jdGlvbmAgaW5zdGVhZCBvZiBgUHJvcFR5cGVzLmZ1bmNgLidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICBlcnIubmFtZSA9ICdJbnZhcmlhbnQgVmlvbGF0aW9uJztcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgICB9XG4gICAgICAgICAgZXJyb3IgPSB0eXBlU3BlY3NbdHlwZVNwZWNOYW1lXSh2YWx1ZXMsIHR5cGVTcGVjTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIG51bGwsIFJlYWN0UHJvcFR5cGVzU2VjcmV0KTtcbiAgICAgICAgfSBjYXRjaCAoZXgpIHtcbiAgICAgICAgICBlcnJvciA9IGV4O1xuICAgICAgICB9XG4gICAgICAgIGlmIChlcnJvciAmJiAhKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpKSB7XG4gICAgICAgICAgcHJpbnRXYXJuaW5nKFxuICAgICAgICAgICAgKGNvbXBvbmVudE5hbWUgfHwgJ1JlYWN0IGNsYXNzJykgKyAnOiB0eXBlIHNwZWNpZmljYXRpb24gb2YgJyArXG4gICAgICAgICAgICBsb2NhdGlvbiArICcgYCcgKyB0eXBlU3BlY05hbWUgKyAnYCBpcyBpbnZhbGlkOyB0aGUgdHlwZSBjaGVja2VyICcgK1xuICAgICAgICAgICAgJ2Z1bmN0aW9uIG11c3QgcmV0dXJuIGBudWxsYCBvciBhbiBgRXJyb3JgIGJ1dCByZXR1cm5lZCBhICcgKyB0eXBlb2YgZXJyb3IgKyAnLiAnICtcbiAgICAgICAgICAgICdZb3UgbWF5IGhhdmUgZm9yZ290dGVuIHRvIHBhc3MgYW4gYXJndW1lbnQgdG8gdGhlIHR5cGUgY2hlY2tlciAnICtcbiAgICAgICAgICAgICdjcmVhdG9yIChhcnJheU9mLCBpbnN0YW5jZU9mLCBvYmplY3RPZiwgb25lT2YsIG9uZU9mVHlwZSwgYW5kICcgK1xuICAgICAgICAgICAgJ3NoYXBlIGFsbCByZXF1aXJlIGFuIGFyZ3VtZW50KS4nXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBFcnJvciAmJiAhKGVycm9yLm1lc3NhZ2UgaW4gbG9nZ2VkVHlwZUZhaWx1cmVzKSkge1xuICAgICAgICAgIC8vIE9ubHkgbW9uaXRvciB0aGlzIGZhaWx1cmUgb25jZSBiZWNhdXNlIHRoZXJlIHRlbmRzIHRvIGJlIGEgbG90IG9mIHRoZVxuICAgICAgICAgIC8vIHNhbWUgZXJyb3IuXG4gICAgICAgICAgbG9nZ2VkVHlwZUZhaWx1cmVzW2Vycm9yLm1lc3NhZ2VdID0gdHJ1ZTtcblxuICAgICAgICAgIHZhciBzdGFjayA9IGdldFN0YWNrID8gZ2V0U3RhY2soKSA6ICcnO1xuXG4gICAgICAgICAgcHJpbnRXYXJuaW5nKFxuICAgICAgICAgICAgJ0ZhaWxlZCAnICsgbG9jYXRpb24gKyAnIHR5cGU6ICcgKyBlcnJvci5tZXNzYWdlICsgKHN0YWNrICE9IG51bGwgPyBzdGFjayA6ICcnKVxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuLyoqXG4gKiBSZXNldHMgd2FybmluZyBjYWNoZSB3aGVuIHRlc3RpbmcuXG4gKlxuICogQHByaXZhdGVcbiAqL1xuY2hlY2tQcm9wVHlwZXMucmVzZXRXYXJuaW5nQ2FjaGUgPSBmdW5jdGlvbigpIHtcbiAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicpIHtcbiAgICBsb2dnZWRUeXBlRmFpbHVyZXMgPSB7fTtcbiAgfVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGNoZWNrUHJvcFR5cGVzO1xuIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUEsWUFBWTs7QUFFWixJQUFJQSxZQUFZLEdBQUcsWUFBVyxDQUFDLENBQUM7QUFFaEMsSUFBSUMsT0FBTyxDQUFDQyxHQUFHLENBQUNDLFFBQVEsS0FBSyxZQUFZLEVB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
}).call(this,require("Xp6JUx"))
},{"./lib/ReactPropTypesSecret":7,"./lib/has":8,"Xp6JUx":2}],4:[function(require,module,exports){
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var ReactPropTypesSecret = require('./lib/ReactPropTypesSecret');
function emptyFunction() {}
function emptyFunctionWithReset() {}
emptyFunctionWithReset.resetWarningCache = emptyFunction;
module.exports = function () {
  function shim(props, propName, componentName, location, propFullName, secret) {
    if (secret === ReactPropTypesSecret) {
      // It is still safe when called from React.
      return;
    }
    var err = new Error('Calling PropTypes validators directly is not supported by the `prop-types` package. ' + 'Use PropTypes.checkPropTypes() to call them. ' + 'Read more at http://fb.me/use-check-prop-types');
    err.name = 'Invariant Violation';
    throw err;
  }
  ;
  shim.isRequired = shim;
  function getShim() {
    return shim;
  }
  ;
  // Important!
  // Keep this list in sync with production version in `./factoryWithTypeCheckers.js`.
  var ReactPropTypes = {
    array: shim,
    bigint: shim,
    bool: shim,
    func: shim,
    number: shim,
    object: shim,
    string: shim,
    symbol: shim,
    any: shim,
    arrayOf: getShim,
    element: shim,
    elementType: shim,
    instanceOf: getShim,
    node: shim,
    objectOf: getShim,
    oneOf: getShim,
    oneOfType: getShim,
    shape: getShim,
    exact: getShim,
    checkPropTypes: emptyFunctionWithReset,
    resetWarningCache: emptyFunction
  };
  ReactPropTypes.PropTypes = ReactPropTypes;
  return ReactPropTypes;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJSZWFjdFByb3BUeXBlc1NlY3JldCIsInJlcXVpcmUiLCJlbXB0eUZ1bmN0aW9uIiwiZW1wdHlGdW5jdGlvbldpdGhSZXNldCIsInJlc2V0V2FybmluZ0NhY2hlIiwibW9kdWxlIiwiZXhwb3J0cyIsInNoaW0iLCJwcm9wcyIsInByb3BOYW1lIiwiY29tcG9uZW50TmFtZSIsImxvY2F0aW9uIiwicHJvcEZ1bGxOYW1lIiwic2VjcmV0IiwiZXJyIiwiRXJyb3IiLCJuYW1lIiwiaXNSZXF1aXJlZCIsImdldFNoaW0iLCJSZWFjdFByb3BUeXBlcyIsImFycmF5IiwiYmlnaW50IiwiYm9vbCIsImZ1bmMiLCJudW1iZXIiLCJvYmplY3QiLCJzdHJpbmciLCJzeW1ib2wiLCJhbnkiLCJhcnJheU9mIiwiZWxlbWVudCIsImVsZW1lbnRUeXBlIiwiaW5zdGFuY2VPZiIsIm5vZGUiLCJvYmplY3RPZiIsIm9uZU9mIiwib25lT2ZUeXBlIiwic2hhcGUiLCJleGFjdCIsImNoZWNrUHJvcFR5cGVzIiwiUHJvcFR5cGVzIl0sInNvdXJjZXMiOlsiZmFjdG9yeVdpdGhUaHJvd2luZ1NoaW1zLmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQ29weXJpZ2h0IChjKSAyMDEzLXByZXNlbnQsIEZhY2Vib29rLCBJbmMuXG4gKlxuICogVGhpcyBzb3VyY2UgY29kZSBpcyBsaWNlbnNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2UgZm91bmQgaW4gdGhlXG4gKiBMSUNFTlNFIGZpbGUgaW4gdGhlIHJvb3QgZGlyZWN0b3J5IG9mIHRoaXMgc291cmNlIHRyZWUuXG4gKi9cblxuJ3VzZSBzdHJpY3QnO1xuXG52YXIgUmVhY3RQcm9wVHlwZXNTZWNyZXQgPSByZXF1aXJlKCcuL2xpYi9SZWFjdFByb3BUeXBlc1NlY3JldCcpO1xuXG5mdW5jdGlvbiBlbXB0eUZ1bmN0aW9uKCkge31cbmZ1bmN0aW9uIGVtcHR5RnVuY3Rpb25XaXRoUmVzZXQoKSB7fVxuZW1wdHlGdW5jdGlvbldpdGhSZXNldC5yZXNldFdhcm5pbmdDYWNoZSA9IGVtcHR5RnVuY3Rpb247XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIHNoaW0ocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lLCBzZWNyZXQpIHtcbiAgICBpZiAoc2VjcmV0ID09PSBSZWFjdFByb3BUeXBlc1NlY3JldCkge1xuICAgICAgLy8gSXQgaXMgc3RpbGwgc2FmZSB3aGVuIGNhbGxlZCBmcm9tIFJlYWN0LlxuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB2YXIgZXJyID0gbmV3IEVycm9yKFxuICAgICAgJ0NhbGxpbmcgUHJvcFR5cGVzIHZhbGlkYXRvcnMgZGlyZWN0bHkgaXMgbm90IHN1cHBvcnRlZCBieSB0aGUgYHByb3AtdHlwZXNgIHBhY2thZ2UuICcgK1xuICAgICAgJ1VzZSBQcm9wVHlwZXMuY2hlY2tQcm9wVHlwZXMoKSB0byBjYWxsIHRoZW0uICcgK1xuICAgICAgJ1JlYWQgbW9yZSBhdCBodHRwOi8vZmIubWUvdXNlLWNoZWNrLXByb3AtdHlwZXMnXG4gICAgKTtcbiAgICBlcnIubmFtZSA9ICdJbnZhcmlhbnQgVmlvbGF0aW9uJztcbiAgICB0aHJvdyBlcnI7XG4gIH07XG4gIHNoaW0uaXNSZXF1aXJlZCA9IHNoaW07XG4gIGZ1bmN0aW9uIGdldFNoaW0oKSB7XG4gICAgcmV0dXJuIHNoaW07XG4gIH07XG4gIC8vIEltcG9ydGFudCFcbiAgLy8gS2VlcCB0aGlzIGxpc3QgaW4gc3luYyB3aXRoIHByb2R1Y3Rpb24gdmVyc2lvbiBpbiBgLi9mYWN0b3J5V2l0aFR5cGVDaGVja2Vycy5qc2AuXG4gIHZhciBSZWFjdFByb3BUeXBlcyA9IHtcbiAgICBhcnJheTogc2hpbSxcbiAgICBiaWdpbnQ6IHNoaW0sXG4gICAgYm9vbDogc2hpbSxcbiAgICBmdW5jOiBzaGltLFxuICAgIG51bWJlcjogc2hpbSxcbiAgICBvYmplY3Q6IHNoaW0sXG4gICAgc3RyaW5nOiBzaGltLFxuICAgIHN5bWJvbDogc2hpbSxcblxuICAgIGFueTogc2hpbSxcbiAgICBhcnJheU9mOiBnZXRTaGltLFxuICAgIGVsZW1lbnQ6IHNoaW0sXG4gICAgZWxlbWVudFR5cGU6IHNoaW0sXG4gICAgaW5zdGFuY2VPZjogZ2V0U2hpbSxcbiAgICBub2RlOiBzaGltLFxuICAgIG9iamVjdE9mOiBnZXRTaGltLFxuICAgIG9uZU9mOiBnZXRTaGltLFxuICAgIG9uZU9mVHlwZTogZ2V0U2hpbSxcbiAgICBzaGFwZTogZ2V0U2hpbSxcbiAgICBleGFjdDogZ2V0U2hpbSxcblxuICAgIGNoZWNrUHJvcFR5cGVzOiBlbXB0eUZ1bmN0aW9uV2l0aFJlc2V0LFxuICAgIHJlc2V0V2FybmluZ0NhY2hlOiBlbXB0eUZ1bmN0aW9uXG4gIH07XG5cbiAgUmVhY3RQcm9wVHlwZXMuUHJvcFR5cGVzID0gUmVhY3RQcm9wVHlwZXM7XG5cbiAgcmV0dXJuIFJlYWN0UHJvcFR5cGVzO1xufTtcbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLFlBQVk7O0FBRVosSUFBSUEsb0JBQW9CLEdBQUdDLE9BQU8sQ0FBQyw0QkFBNEIsQ0FBQztBQUVoRSxTQUFTQyxhQUFhLEdBQUcsQ0FBQztBQUMxQixTQUFTQyxzQkFBc0IsR0FBRyxDQUFDO0FBQ25DQSxzQkFBc0IsQ0FBQ0MsaUJBQWlCLEdBQUdGLGFBQWE7QUFFeERHLE1BQU0sQ0FBQ0MsT0FBTyxHQUFHLFlBQVc7RUFDMUIsU0FBU0MsSUFBSSxDQUFDQyxLQUFLLEVBQUVDLFFBQVEsRUFBRUMsYUFBYSxFQUFFQyxRQUFRLEVBQUVDLFlBQVksRUFBRUMsTUFBTSxFQUFFO0lBQzVFLElBQUlBLE1BQU0sS0FBS2Isb0JBQW9CLEVBQUU7TUFDbkM7TUFDQTtJQUNGO0lBQ0EsSUFBSWMsR0FBRyxHQUFHLElBQUlDLEtBQUssQ0FDakIsc0ZBQXNGLEdBQ3RGLCtDQUErQyxHQUMvQyxnREFBZ0QsQ0FDakQ7SUFDREQsR0FBRyxDQUFDRSxJQUFJLEdBQUcscUJBQXFCO0lBQ2hDLE1BQU1GLEdBQUc7RUFDWDtFQUFDO0VBQ0RQLElBQUksQ0FBQ1UsVUFBVSxHQUFHVixJQUFJO0VBQ3RCLFNBQVNXLE9BQU8sR0FBRztJQUNqQixPQUFPWCxJQUFJO0VBQ2I7RUFBQztFQUNEO0VBQ0E7RUFDQSxJQUFJWSxjQUFjLEdBQUc7SUFDbkJDLEtBQUssRUFBRWIsSUFBSTtJQUNYYyxNQUFNLEVBQUVkLElBQUk7SUFDWmUsSUFBSSxFQUFFZixJQUFJO0lBQ1ZnQixJQUFJLEVBQUVoQixJQUFJO0lBQ1ZpQixNQUFNLEVBQUVqQixJQUFJO0lBQ1prQixNQUFNLEVBQUVsQixJQUFJO0lBQ1ptQixNQUFNLEVBQUVuQixJQUFJO0lBQ1pvQixNQUFNLEVBQUVwQixJQUFJO0lBRVpxQixHQUFHLEVBQUVyQixJQUFJO0lBQ1RzQixPQUFPLEVBQUVYLE9BQU87SUFDaEJZLE9BQU8sRUFBRXZCLElBQUk7SUFDYndCLFdBQVcsRUFBRXhCLElBQUk7SUFDakJ5QixVQUFVLEVBQUVkLE9BQU87SUFDbkJlLElBQUksRUFBRTFCLElBQUk7SUFDVjJCLFFBQVEsRUFBRWhCLE9BQU87SUFDakJpQixLQUFLLEVBQUVqQixPQUFPO0lBQ2RrQixTQUFTLEVBQUVsQixPQUFPO0lBQ2xCbUIsS0FBSyxFQUFFbkIsT0FBTztJQUNkb0IsS0FBSyxFQUFFcEIsT0FBTztJQUVkcUIsY0FBYyxFQUFFcEMsc0JBQXNCO0lBQ3RDQyxpQkFBaUIsRUFBRUY7RUFDckIsQ0FBQztFQUVEaUIsY0FBYyxDQUFDcUIsU0FBUyxHQUFHckIsY0FBYztFQUV6QyxPQUFPQSxjQUFjO0FBQ3ZCLENBQUMifQ==
},{"./lib/ReactPropTypesSecret":7}],5:[function(require,module,exports){
(function (process){
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var ReactIs = require('react-is');
var assign = require('object-assign');
var ReactPropTypesSecret = require('./lib/ReactPropTypesSecret');
var has = require('./lib/has');
var checkPropTypes = require('./checkPropTypes');
var printWarning = function () {};
if (process.env.NODE_ENV !== 'production') {
  printWarning = function (text) {
    var message = 'Warning: ' + text;
    if (typeof console !== 'undefined') {
      console.error(message);
    }
    try {
      // --- Welcome to debugging React ---
      // This error was thrown as a convenience so that you can use this stack
      // to find the callsite that caused this warning to fire.
      throw new Error(message);
    } catch (x) {}
  };
}
function emptyFunctionThatReturnsNull() {
  return null;
}
module.exports = function (isValidElement, throwOnDirectAccess) {
  /* global Symbol */
  var ITERATOR_SYMBOL = typeof Symbol === 'function' && Symbol.iterator;
  var FAUX_ITERATOR_SYMBOL = '@@iterator'; // Before Symbol spec.

  /**
   * Returns the iterator method function contained on the iterable object.
   *
   * Be sure to invoke the function with the iterable as context:
   *
   *     var iteratorFn = getIteratorFn(myIterable);
   *     if (iteratorFn) {
   *       var iterator = iteratorFn.call(myIterable);
   *       ...
   *     }
   *
   * @param {?object} maybeIterable
   * @return {?function}
   */
  function getIteratorFn(maybeIterable) {
    var iteratorFn = maybeIterable && (ITERATOR_SYMBOL && maybeIterable[ITERATOR_SYMBOL] || maybeIterable[FAUX_ITERATOR_SYMBOL]);
    if (typeof iteratorFn === 'function') {
      return iteratorFn;
    }
  }

  /**
   * Collection of methods that allow declaration and validation of props that are
   * supplied to React components. Example usage:
   *
   *   var Props = require('ReactPropTypes');
   *   var MyArticle = React.createClass({
   *     propTypes: {
   *       // An optional string prop named "description".
   *       description: Props.string,
   *
   *       // A required enum prop named "category".
   *       category: Props.oneOf(['News','Photos']).isRequired,
   *
   *       // A prop named "dialog" that requires an instance of Dialog.
   *       dialog: Props.instanceOf(Dialog).isRequired
   *     },
   *     render: function() { ... }
   *   });
   *
   * A more formal specification of how these methods are used:
   *
   *   type := array|bool|func|object|number|string|oneOf([...])|instanceOf(...)
   *   decl := ReactPropTypes.{type}(.isRequired)?
   *
   * Each and every declaration produces a function with the same signature. This
   * allows the creation of custom validation functions. For example:
   *
   *  var MyLink = React.createClass({
   *    propTypes: {
   *      // An optional string or URI prop named "href".
   *      href: function(props, propName, componentName) {
   *        var propValue = props[propName];
   *        if (propValue != null && typeof propValue !== 'string' &&
   *            !(propValue instanceof URI)) {
   *          return new Error(
   *            'Expected a string or an URI for ' + propName + ' in ' +
   *            componentName
   *          );
   *        }
   *      }
   *    },
   *    render: function() {...}
   *  });
   *
   * @internal
   */

  var ANONYMOUS = '<<anonymous>>';

  // Important!
  // Keep this list in sync with production version in `./factoryWithThrowingShims.js`.
  var ReactPropTypes = {
    array: createPrimitiveTypeChecker('array'),
    bigint: createPrimitiveTypeChecker('bigint'),
    bool: createPrimitiveTypeChecker('boolean'),
    func: createPrimitiveTypeChecker('function'),
    number: createPrimitiveTypeChecker('number'),
    object: createPrimitiveTypeChecker('object'),
    string: createPrimitiveTypeChecker('string'),
    symbol: createPrimitiveTypeChecker('symbol'),
    any: createAnyTypeChecker(),
    arrayOf: createArrayOfTypeChecker,
    element: createElementTypeChecker(),
    elementType: createElementTypeTypeChecker(),
    instanceOf: createInstanceTypeChecker,
    node: createNodeChecker(),
    objectOf: createObjectOfTypeChecker,
    oneOf: createEnumTypeChecker,
    oneOfType: createUnionTypeChecker,
    shape: createShapeTypeChecker,
    exact: createStrictShapeTypeChecker
  };

  /**
   * inlined Object.is polyfill to avoid requiring consumers ship their own
   * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/is
   */
  /*eslint-disable no-self-compare*/
  function is(x, y) {
    // SameValue algorithm
    if (x === y) {
      // Steps 1-5, 7-10
      // Steps 6.b-6.e: +0 != -0
      return x !== 0 || 1 / x === 1 / y;
    } else {
      // Step 6.a: NaN == NaN
      return x !== x && y !== y;
    }
  }
  /*eslint-enable no-self-compare*/

  /**
   * We use an Error-like object for backward compatibility as people may call
   * PropTypes directly and inspect their output. However, we don't use real
   * Errors anymore. We don't inspect their stack anyway, and creating them
   * is prohibitively expensive if they are created too often, such as what
   * happens in oneOfType() for any type before the one that matched.
   */
  function PropTypeError(message, data) {
    this.message = message;
    this.data = data && typeof data === 'object' ? data : {};
    this.stack = '';
  }
  // Make `instanceof Error` still work for returned errors.
  PropTypeError.prototype = Error.prototype;
  function createChainableTypeChecker(validate) {
    if (process.env.NODE_ENV !== 'production') {
      var manualPropTypeCallCache = {};
      var manualPropTypeWarningCount = 0;
    }
    function checkType(isRequired, props, propName, componentName, location, propFullName, secret) {
      componentName = componentName || ANONYMOUS;
      propFullName = propFullName || propName;
      if (secret !== ReactPropTypesSecret) {
        if (throwOnDirectAccess) {
          // New behavior only for users of `prop-types` package
          var err = new Error('Calling PropTypes validators directly is not supported by the `prop-types` package. ' + 'Use `PropTypes.checkPropTypes()` to call them. ' + 'Read more at http://fb.me/use-check-prop-types');
          err.name = 'Invariant Violation';
          throw err;
        } else if (process.env.NODE_ENV !== 'production' && typeof console !== 'undefined') {
          // Old behavior for people using React.PropTypes
          var cacheKey = componentName + ':' + propName;
          if (!manualPropTypeCallCache[cacheKey] &&
          // Avoid spamming the console because they are often not actionable except for lib authors
          manualPropTypeWarningCount < 3) {
            printWarning('You are manually calling a React.PropTypes validation ' + 'function for the `' + propFullName + '` prop on `' + componentName + '`. This is deprecated ' + 'and will throw in the standalone `prop-types` package. ' + 'You may be seeing this warning due to a third-party PropTypes ' + 'library. See https://fb.me/react-warning-dont-call-proptypes ' + 'for details.');
            manualPropTypeCallCache[cacheKey] = true;
            manualPropTypeWarningCount++;
          }
        }
      }
      if (props[propName] == null) {
        if (isRequired) {
          if (props[propName] === null) {
            return new PropTypeError('The ' + location + ' `' + propFullName + '` is marked as required ' + ('in `' + componentName + '`, but its value is `null`.'));
          }
          return new PropTypeError('The ' + location + ' `' + propFullName + '` is marked as required in ' + ('`' + componentName + '`, but its value is `undefined`.'));
        }
        return null;
      } else {
        return validate(props, propName, componentName, location, propFullName);
      }
    }
    var chainedCheckType = checkType.bind(null, false);
    chainedCheckType.isRequired = checkType.bind(null, true);
    return chainedCheckType;
  }
  function createPrimitiveTypeChecker(expectedType) {
    function validate(props, propName, componentName, location, propFullName, secret) {
      var propValue = props[propName];
      var propType = getPropType(propValue);
      if (propType !== expectedType) {
        // `propValue` being instance of, say, date/regexp, pass the 'object'
        // check, but we can offer a more precise error message here rather than
        // 'of type `object`'.
        var preciseType = getPreciseType(propValue);
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + preciseType + '` supplied to `' + componentName + '`, expected ') + ('`' + expectedType + '`.'), {
          expectedType: expectedType
        });
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createAnyTypeChecker() {
    return createChainableTypeChecker(emptyFunctionThatReturnsNull);
  }
  function createArrayOfTypeChecker(typeChecker) {
    function validate(props, propName, componentName, location, propFullName) {
      if (typeof typeChecker !== 'function') {
        return new PropTypeError('Property `' + propFullName + '` of component `' + componentName + '` has invalid PropType notation inside arrayOf.');
      }
      var propValue = props[propName];
      if (!Array.isArray(propValue)) {
        var propType = getPropType(propValue);
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + propType + '` supplied to `' + componentName + '`, expected an array.'));
      }
      for (var i = 0; i < propValue.length; i++) {
        var error = typeChecker(propValue, i, componentName, location, propFullName + '[' + i + ']', ReactPropTypesSecret);
        if (error instanceof Error) {
          return error;
        }
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createElementTypeChecker() {
    function validate(props, propName, componentName, location, propFullName) {
      var propValue = props[propName];
      if (!isValidElement(propValue)) {
        var propType = getPropType(propValue);
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + propType + '` supplied to `' + componentName + '`, expected a single ReactElement.'));
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createElementTypeTypeChecker() {
    function validate(props, propName, componentName, location, propFullName) {
      var propValue = props[propName];
      if (!ReactIs.isValidElementType(propValue)) {
        var propType = getPropType(propValue);
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + propType + '` supplied to `' + componentName + '`, expected a single ReactElement type.'));
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createInstanceTypeChecker(expectedClass) {
    function validate(props, propName, componentName, location, propFullName) {
      if (!(props[propName] instanceof expectedClass)) {
        var expectedClassName = expectedClass.name || ANONYMOUS;
        var actualClassName = getClassName(props[propName]);
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + actualClassName + '` supplied to `' + componentName + '`, expected ') + ('instance of `' + expectedClassName + '`.'));
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createEnumTypeChecker(expectedValues) {
    if (!Array.isArray(expectedValues)) {
      if (process.env.NODE_ENV !== 'production') {
        if (arguments.length > 1) {
          printWarning('Invalid arguments supplied to oneOf, expected an array, got ' + arguments.length + ' arguments. ' + 'A common mistake is to write oneOf(x, y, z) instead of oneOf([x, y, z]).');
        } else {
          printWarning('Invalid argument supplied to oneOf, expected an array.');
        }
      }
      return emptyFunctionThatReturnsNull;
    }
    function validate(props, propName, componentName, location, propFullName) {
      var propValue = props[propName];
      for (var i = 0; i < expectedValues.length; i++) {
        if (is(propValue, expectedValues[i])) {
          return null;
        }
      }
      var valuesString = JSON.stringify(expectedValues, function replacer(key, value) {
        var type = getPreciseType(value);
        if (type === 'symbol') {
          return String(value);
        }
        return value;
      });
      return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of value `' + String(propValue) + '` ' + ('supplied to `' + componentName + '`, expected one of ' + valuesString + '.'));
    }
    return createChainableTypeChecker(validate);
  }
  function createObjectOfTypeChecker(typeChecker) {
    function validate(props, propName, componentName, location, propFullName) {
      if (typeof typeChecker !== 'function') {
        return new PropTypeError('Property `' + propFullName + '` of component `' + componentName + '` has invalid PropType notation inside objectOf.');
      }
      var propValue = props[propName];
      var propType = getPropType(propValue);
      if (propType !== 'object') {
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type ' + ('`' + propType + '` supplied to `' + componentName + '`, expected an object.'));
      }
      for (var key in propValue) {
        if (has(propValue, key)) {
          var error = typeChecker(propValue, key, componentName, location, propFullName + '.' + key, ReactPropTypesSecret);
          if (error instanceof Error) {
            return error;
          }
        }
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createUnionTypeChecker(arrayOfTypeCheckers) {
    if (!Array.isArray(arrayOfTypeCheckers)) {
      process.env.NODE_ENV !== 'production' ? printWarning('Invalid argument supplied to oneOfType, expected an instance of array.') : void 0;
      return emptyFunctionThatReturnsNull;
    }
    for (var i = 0; i < arrayOfTypeCheckers.length; i++) {
      var checker = arrayOfTypeCheckers[i];
      if (typeof checker !== 'function') {
        printWarning('Invalid argument supplied to oneOfType. Expected an array of check functions, but ' + 'received ' + getPostfixForTypeWarning(checker) + ' at index ' + i + '.');
        return emptyFunctionThatReturnsNull;
      }
    }
    function validate(props, propName, componentName, location, propFullName) {
      var expectedTypes = [];
      for (var i = 0; i < arrayOfTypeCheckers.length; i++) {
        var checker = arrayOfTypeCheckers[i];
        var checkerResult = checker(props, propName, componentName, location, propFullName, ReactPropTypesSecret);
        if (checkerResult == null) {
          return null;
        }
        if (checkerResult.data && has(checkerResult.data, 'expectedType')) {
          expectedTypes.push(checkerResult.data.expectedType);
        }
      }
      var expectedTypesMessage = expectedTypes.length > 0 ? ', expected one of type [' + expectedTypes.join(', ') + ']' : '';
      return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` supplied to ' + ('`' + componentName + '`' + expectedTypesMessage + '.'));
    }
    return createChainableTypeChecker(validate);
  }
  function createNodeChecker() {
    function validate(props, propName, componentName, location, propFullName) {
      if (!isNode(props[propName])) {
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` supplied to ' + ('`' + componentName + '`, expected a ReactNode.'));
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function invalidValidatorError(componentName, location, propFullName, key, type) {
    return new PropTypeError((componentName || 'React class') + ': ' + location + ' type `' + propFullName + '.' + key + '` is invalid; ' + 'it must be a function, usually from the `prop-types` package, but received `' + type + '`.');
  }
  function createShapeTypeChecker(shapeTypes) {
    function validate(props, propName, componentName, location, propFullName) {
      var propValue = props[propName];
      var propType = getPropType(propValue);
      if (propType !== 'object') {
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type `' + propType + '` ' + ('supplied to `' + componentName + '`, expected `object`.'));
      }
      for (var key in shapeTypes) {
        var checker = shapeTypes[key];
        if (typeof checker !== 'function') {
          return invalidValidatorError(componentName, location, propFullName, key, getPreciseType(checker));
        }
        var error = checker(propValue, key, componentName, location, propFullName + '.' + key, ReactPropTypesSecret);
        if (error) {
          return error;
        }
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function createStrictShapeTypeChecker(shapeTypes) {
    function validate(props, propName, componentName, location, propFullName) {
      var propValue = props[propName];
      var propType = getPropType(propValue);
      if (propType !== 'object') {
        return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` of type `' + propType + '` ' + ('supplied to `' + componentName + '`, expected `object`.'));
      }
      // We need to check all keys in case some are required but missing from props.
      var allKeys = assign({}, props[propName], shapeTypes);
      for (var key in allKeys) {
        var checker = shapeTypes[key];
        if (has(shapeTypes, key) && typeof checker !== 'function') {
          return invalidValidatorError(componentName, location, propFullName, key, getPreciseType(checker));
        }
        if (!checker) {
          return new PropTypeError('Invalid ' + location + ' `' + propFullName + '` key `' + key + '` supplied to `' + componentName + '`.' + '\nBad object: ' + JSON.stringify(props[propName], null, '  ') + '\nValid keys: ' + JSON.stringify(Object.keys(shapeTypes), null, '  '));
        }
        var error = checker(propValue, key, componentName, location, propFullName + '.' + key, ReactPropTypesSecret);
        if (error) {
          return error;
        }
      }
      return null;
    }
    return createChainableTypeChecker(validate);
  }
  function isNode(propValue) {
    switch (typeof propValue) {
      case 'number':
      case 'string':
      case 'undefined':
        return true;
      case 'boolean':
        return !propValue;
      case 'object':
        if (Array.isArray(propValue)) {
          return propValue.every(isNode);
        }
        if (propValue === null || isValidElement(propValue)) {
          return true;
        }
        var iteratorFn = getIteratorFn(propValue);
        if (iteratorFn) {
          var iterator = iteratorFn.call(propValue);
          var step;
          if (iteratorFn !== propValue.entries) {
            while (!(step = iterator.next()).done) {
              if (!isNode(step.value)) {
                return false;
              }
            }
          } else {
            // Iterator will provide entry [k,v] tuples rather than values.
            while (!(step = iterator.next()).done) {
              var entry = step.value;
              if (entry) {
                if (!isNode(entry[1])) {
                  return false;
                }
              }
            }
          }
        } else {
          return false;
        }
        return true;
      default:
        return false;
    }
  }
  function isSymbol(propType, propValue) {
    // Native Symbol.
    if (propType === 'symbol') {
      return true;
    }

    // falsy value can't be a Symbol
    if (!propValue) {
      return false;
    }

    // 19.4.3.5 Symbol.prototype[@@toStringTag] === 'Symbol'
    if (propValue['@@toStringTag'] === 'Symbol') {
      return true;
    }

    // Fallback for non-spec compliant Symbols which are polyfilled.
    if (typeof Symbol === 'function' && propValue instanceof Symbol) {
      return true;
    }
    return false;
  }

  // Equivalent of `typeof` but with special handling for array and regexp.
  function getPropType(propValue) {
    var propType = typeof propValue;
    if (Array.isArray(propValue)) {
      return 'array';
    }
    if (propValue instanceof RegExp) {
      // Old webkits (at least until Android 4.0) return 'function' rather than
      // 'object' for typeof a RegExp. We'll normalize this here so that /bla/
      // passes PropTypes.object.
      return 'object';
    }
    if (isSymbol(propType, propValue)) {
      return 'symbol';
    }
    return propType;
  }

  // This handles more types than `getPropType`. Only used for error messages.
  // See `createPrimitiveTypeChecker`.
  function getPreciseType(propValue) {
    if (typeof propValue === 'undefined' || propValue === null) {
      return '' + propValue;
    }
    var propType = getPropType(propValue);
    if (propType === 'object') {
      if (propValue instanceof Date) {
        return 'date';
      } else if (propValue instanceof RegExp) {
        return 'regexp';
      }
    }
    return propType;
  }

  // Returns a string that is postfixed to a warning about an invalid type.
  // For example, "undefined" or "of type array"
  function getPostfixForTypeWarning(value) {
    var type = getPreciseType(value);
    switch (type) {
      case 'array':
      case 'object':
        return 'an ' + type;
      case 'boolean':
      case 'date':
      case 'regexp':
        return 'a ' + type;
      default:
        return type;
    }
  }

  // Returns class name of the object, if any.
  function getClassName(propValue) {
    if (!propValue.constructor || !propValue.constructor.name) {
      return ANONYMOUS;
    }
    return propValue.constructor.name;
  }
  ReactPropTypes.checkPropTypes = checkPropTypes;
  ReactPropTypes.resetWarningCache = checkPropTypes.resetWarningCache;
  ReactPropTypes.PropTypes = ReactPropTypes;
  return ReactPropTypes;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJSZWFjdElzIiwicmVxdWlyZSIsImFzc2lnbiIsIlJlYWN0UHJvcFR5cGVzU2VjcmV0IiwiaGFzIiwiY2hlY2tQcm9wVHlwZXMiLCJwcmludFdhcm5pbmciLCJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJ0ZXh0IiwibWVzc2FnZSIsImNvbnNvbGUiLCJlcnJvciIsIkVycm9yIiwieCIsImVtcHR5RnVuY3Rpb25UaGF0UmV0dXJuc051bGwiLCJtb2R1bGUiLCJleHBvcnRzIiwiaXNWYWxpZEVsZW1lbnQiLCJ0aHJvd09uRGlyZWN0QWNjZXNzIiwiSVRFUkFUT1JfU1lNQk9MIiwiU3ltYm9sIiwiaXRlcmF0b3IiLCJGQVVYX0lURVJBVE9SX1NZTUJPTCIsImdldEl0ZXJhdG9yRm4iLCJtYXliZUl0ZXJhYmxlIiwiaXRlcmF0b3JGbiIsIkFOT05ZTU9VUyIsIlJlYWN0UHJvcFR5cGVzIiwiYXJyYXkiLCJjcmVhdGVQcmltaXRpdmVUeXBlQ2hlY2tlciIsImJpZ2ludCIsImJvb2wiLCJmdW5jIiwibnVtYmVyIiwib2JqZWN0Iiwic3RyaW5nIiwic3ltYm9sIiwiYW55IiwiY3JlYXRlQW55VHlwZUNoZWNrZXIiLCJhcnJheU9mIiwiY3JlYXRlQXJyYXlPZlR5cGVDaGVja2VyIiwiZWxlbWVudCIsImNyZWF0ZUVsZW1lbnRUeXBlQ2hlY2tlciIsImVsZW1lbnRUeXBlIiwiY3JlYXRlRWxlbWVudFR5cGVUeXBlQ2hlY2tlciIsImluc3RhbmNlT2YiLCJjcmVhdGVJbnN0YW5jZVR5cGVDaGVja2VyIiwibm9kZSIsImNyZWF0ZU5vZGVDaGVja2VyIiwib2JqZWN0T2YiLCJjcmVhdGVPYmplY3RPZlR5cGVDaGVja2VyIiwib25lT2YiLCJjcmVhdGVFbnVtVHlwZUNoZWNrZXIiLCJvbmVPZlR5cGUiLCJjcmVhdGVVbmlvblR5cGVDaGVja2VyIiwic2hhcGUiLCJjcmVhdGVTaGFwZVR5cGVDaGVja2VyIiwiZXhhY3QiLCJjcmVhdGVTdHJpY3RTaGFwZVR5cGVDaGVja2VyIiwiaXMiLCJ5IiwiUHJvcFR5cGVFcnJvciIsImRhdGEiLCJzdGFjayIsInByb3RvdHlwZSIsImNyZWF0ZUNoYWluYWJsZVR5cGVDaGVja2VyIiwidmFsaWRhdGUiLCJtYW51YWxQcm9wVHlwZUNhbGxDYWNoZSIsIm1hbnVhbFByb3BUeXBlV2FybmluZ0NvdW50IiwiY2hlY2tUeXBlIiwiaXNSZXF1aXJlZCIsInByb3BzIiwicHJvcE5hbWUiLCJjb21wb25lbnROYW1lIiwibG9jYXRpb24iLCJwcm9wRnVsbE5hbWUiLCJzZWNyZXQiLCJlcnIiLCJuYW1lIiwiY2FjaGVLZXkiLCJjaGFpbmVkQ2hlY2tUeXBlIiwiYmluZCIsImV4cGVjdGVkVHlwZSIsInByb3BWYWx1ZSIsInByb3BUeXBlIiwiZ2V0UHJvcFR5cGUiLCJwcmVjaXNlVHlwZSIsImdldFByZWNpc2VUeXBlIiwidHlwZUNoZWNrZXIiLCJBcnJheSIsImlzQXJyYXkiLCJpIiwibGVuZ3RoIiwiaXNWYWxpZEVsZW1lbnRUeXBlIiwiZXhwZWN0ZWRDbGFzcyIsImV4cGVjdGVkQ2xhc3NOYW1lIiwiYWN0dWFsQ2xhc3NOYW1lIiwiZ2V0Q2xhc3NOYW1lIiwiZXhwZWN0ZWRWYWx1ZXMiLCJhcmd1bWVudHMiLCJ2YWx1ZXNTdHJpbmciLCJKU09OIiwic3RyaW5naWZ5IiwicmVwbGFjZXIiLCJrZXkiLCJ2YWx1ZSIsInR5cGUiLCJTdHJpbmciLCJhcnJheU9mVHlwZUNoZWNrZXJzIiwiY2hlY2tlciIsImdldFBvc3RmaXhGb3JUeXBlV2FybmluZyIsImV4cGVjdGVkVHlwZXMiLCJjaGVja2VyUmVzdWx0IiwicHVzaCIsImV4cGVjdGVkVHlwZXNNZXNzYWdlIiwiam9pbiIsImlzTm9kZSIsImludmFsaWRWYWxpZGF0b3JFcnJvciIsInNoYXBlVHlwZXMiLCJhbGxLZXlzIiwiT2JqZWN0Iiwia2V5cyIsImV2ZXJ5IiwiY2FsbCIsInN0ZXAiLCJlbnRyaWVzIiwibmV4dCIsImRvbmUiLCJlbnRyeSIsImlzU3ltYm9sIiwiUmVnRXhwIiwiRGF0ZSIsImNvbnN0cnVjdG9yIiwicmVzZXRXYXJuaW5nQ2FjaGUiLCJQcm9wVHlwZXMiXSwic291cmNlcyI6WyJmYWN0b3J5V2l0aFR5cGVDaGVja2Vycy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIENvcHlyaWdodCAoYykgMjAxMy1wcmVzZW50LCBGYWNlYm9vaywgSW5jLlxuICpcbiAqIFRoaXMgc291cmNlIGNvZGUgaXMgbGljZW5zZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlIGZvdW5kIGluIHRoZVxuICogTElDRU5TRSBmaWxlIGluIHRoZSByb290IGRpcmVjdG9yeSBvZiB0aGlzIHNvdXJjZSB0cmVlLlxuICovXG5cbid1c2Ugc3RyaWN0JztcblxudmFyIFJlYWN0SXMgPSByZXF1aXJlKCdyZWFjdC1pcycpO1xudmFyIGFzc2lnbiA9IHJlcXVpcmUoJ29iamVjdC1hc3NpZ24nKTtcblxudmFyIFJlYWN0UHJvcFR5cGVzU2VjcmV0ID0gcmVxdWlyZSgnLi9saWIvUmVhY3RQcm9wVHlwZXNTZWNyZXQnKTtcbnZhciBoYXMgPSByZXF1aXJlKCcuL2xpYi9oYXMnKTtcbnZhciBjaGVja1Byb3BUeXBlcyA9IHJlcXVpcmUoJy4vY2hlY2tQcm9wVHlwZXMnKTtcblxudmFyIHByaW50V2FybmluZyA9IGZ1bmN0aW9uKCkge307XG5cbmlmIChwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG4gIHByaW50V2FybmluZyA9IGZ1bmN0aW9uKHRleHQpIHtcbiAgICB2YXIgbWVzc2FnZSA9ICdXYXJuaW5nOiAnICsgdGV4dDtcbiAgICBpZiAodHlwZW9mIGNvbnNvbGUgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICBjb25zb2xlLmVycm9yKG1lc3NhZ2UpO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgLy8gLS0tIFdlbGNvbWUgdG8gZGVidWdnaW5nIFJlYWN0IC0tLVxuICAgICAgLy8gVGhpcyBlcnJvciB3YXMgdGhyb3duIGFzIGEgY29udmVuaWVuY2Ugc28gdGhhdCB5b3UgY2FuIHVzZSB0aGlzIHN0YWNrXG4gICAgICAvLyB0byBmaW5kIHRoZSBjYWxsc2l0ZSB0aGF0IGNhdXNlZCB0aGlzIHdhcm5pbmcgdG8gZmlyZS5cbiAgICAgIHRocm93IG5ldyBFcnJvcihtZXNzYWdlKTtcbiAgICB9IGNhdGNoICh4KSB7fVxuICB9O1xufVxuXG5mdW5jdGlvbiBlbXB0eUZ1bmN0aW9uVGhhdFJldHVybnNOdWxsKCkge1xuICByZXR1cm4gbnVsbDtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihpc1ZhbGlkRWxlbWVudCwgdGhyb3dPbkRpcmVjdEFjY2Vzcykge1xuICAvKiBnbG9iYWwgU3ltYm9sICovXG4gIHZhciBJVEVSQVRPUl9TWU1CT0wgPSB0eXBlb2YgU3ltYm9sID09PSAnZnVuY3Rpb24nICYmIFN5bWJvbC5pdGVyYXRvcjtcbiAgdmFyIEZBVVhfSVRFUkFUT1JfU1lNQk9MID0gJ0BAaXRlcmF0b3InOyAvLyBCZWZvcmUgU3ltYm9sIHNwZWMuXG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGl0ZXJhdG9yIG1ldGhvZCBmdW5jdGlvbiBjb250YWluZWQgb24gdGhlIGl0ZXJhYmxlIG9iamVjdC5cbiAgICpcbiAgICogQmUgc3VyZSB0byBpbnZva2UgdGhlIGZ1bmN0aW9uIHdpdGggdGhlIGl0ZXJhYmxlIGFzIGNvbnRleHQ6XG4gICAqXG4gICAqICAgICB2YXIgaXRlcmF0b3JGbiA9IGdldEl0ZXJhdG9yRm4obXlJdGVyYWJsZSk7XG4gICAqICAgICBpZiAoaXRlcmF0b3JGbikge1xuICAgKiAgICAgICB2YXIgaXRlcmF0b3IgPSBpdGVyYXRvckZuLmNhbGwobXlJdGVyYWJsZSk7XG4gICAqICAgICAgIC4uLlxuICAgKiAgICAgfVxuICAgKlxuICAgKiBAcGFyYW0gez9vYmplY3R9IG1heWJlSXRlcmFibGVcbiAgICogQHJldHVybiB7P2Z1bmN0aW9ufVxuICAgKi9cbiAgZnVuY3Rpb24gZ2V0SXRlcmF0b3JGbihtYXliZUl0ZXJhYmxlKSB7XG4gICAgdmFyIGl0ZXJhdG9yRm4gPSBtYXliZUl0ZXJhYmxlICYmIChJVEVSQVRPUl9TWU1CT0wgJiYgbWF5YmVJdGVyYWJsZVtJVEVSQVRPUl9TWU1CT0xdIHx8IG1heWJlSXRlcmFibGVbRkFVWF9JVEVSQVRPUl9TWU1CT0xdKTtcbiAgICBpZiAodHlwZW9mIGl0ZXJhdG9yRm4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHJldHVybiBpdGVyYXRvckZuO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBDb2xsZWN0aW9uIG9mIG1ldGhvZHMgdGhhdCBhbGxvdyBkZWNsYXJhdGlvbiBhbmQgdmFsaWRhdGlvbiBvZiBwcm9wcyB0aGF0IGFyZVxuICAgKiBzdXBwbGllZCB0byBSZWFjdCBjb21wb25lbnRzLiBFeGFtcGxlIHVzYWdlOlxuICAgKlxuICAgKiAgIHZhciBQcm9wcyA9IHJlcXVpcmUoJ1JlYWN0UHJvcFR5cGVzJyk7XG4gICAqICAgdmFyIE15QXJ0aWNsZSA9IFJlYWN0LmNyZWF0ZUNsYXNzKHtcbiAgICogICAgIHByb3BUeXBlczoge1xuICAgKiAgICAgICAvLyBBbiBvcHRpb25hbCBzdHJpbmcgcHJvcCBuYW1lZCBcImRlc2NyaXB0aW9uXCIuXG4gICAqICAgICAgIGRlc2NyaXB0aW9uOiBQcm9wcy5zdHJpbmcsXG4gICAqXG4gICAqICAgICAgIC8vIEEgcmVxdWlyZWQgZW51bSBwcm9wIG5hbWVkIFwiY2F0ZWdvcnlcIi5cbiAgICogICAgICAgY2F0ZWdvcnk6IFByb3BzLm9uZU9mKFsnTmV3cycsJ1Bob3RvcyddKS5pc1JlcXVpcmVkLFxuICAgKlxuICAgKiAgICAgICAvLyBBIHByb3AgbmFtZWQgXCJkaWFsb2dcIiB0aGF0IHJlcXVpcmVzIGFuIGluc3RhbmNlIG9mIERpYWxvZy5cbiAgICogICAgICAgZGlhbG9nOiBQcm9wcy5pbnN0YW5jZU9mKERpYWxvZykuaXNSZXF1aXJlZFxuICAgKiAgICAgfSxcbiAgICogICAgIHJlbmRlcjogZnVuY3Rpb24oKSB7IC4uLiB9XG4gICAqICAgfSk7XG4gICAqXG4gICAqIEEgbW9yZSBmb3JtYWwgc3BlY2lmaWNhdGlvbiBvZiBob3cgdGhlc2UgbWV0aG9kcyBhcmUgdXNlZDpcbiAgICpcbiAgICogICB0eXBlIDo9IGFycmF5fGJvb2x8ZnVuY3xvYmplY3R8bnVtYmVyfHN0cmluZ3xvbmVPZihbLi4uXSl8aW5zdGFuY2VPZiguLi4pXG4gICAqICAgZGVjbCA6PSBSZWFjdFByb3BUeXBlcy57dHlwZX0oLmlzUmVxdWlyZWQpP1xuICAgKlxuICAgKiBFYWNoIGFuZCBldmVyeSBkZWNsYXJhdGlvbiBwcm9kdWNlcyBhIGZ1bmN0aW9uIHdpdGggdGhlIHNhbWUgc2lnbmF0dXJlLiBUaGlzXG4gICAqIGFsbG93cyB0aGUgY3JlYXRpb24gb2YgY3VzdG9tIHZhbGlkYXRpb24gZnVuY3Rpb25zLiBGb3IgZXhhbXBsZTpcbiAgICpcbiAgICogIHZhciBNeUxpbmsgPSBSZWFjdC5jcmVhdGVDbGFzcyh7XG4gICAqICAgIHByb3BUeXBlczoge1xuICAgKiAgICAgIC8vIEFuIG9wdGlvbmFsIHN0cmluZyBvciBVUkkgcHJvcCBuYW1lZCBcImhyZWZcIi5cbiAgICogICAgICBocmVmOiBmdW5jdGlvbihwcm9wcywgcHJvcE5hbWUsIGNvbXBvbmVudE5hbWUpIHtcbiAgICogICAgICAgIHZhciBwcm9wVmFsdWUgPSBwcm9wc1twcm9wTmFtZV07XG4gICAqICAgICAgICBpZiAocHJvcFZhbHVlICE9IG51bGwgJiYgdHlwZW9mIHByb3BWYWx1ZSAhPT0gJ3N0cmluZycgJiZcbiAgICogICAgICAgICAgICAhKHByb3BWYWx1ZSBpbnN0YW5jZW9mIFVSSSkpIHtcbiAgICogICAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcbiAgICogICAgICAgICAgICAnRXhwZWN0ZWQgYSBzdHJpbmcgb3IgYW4gVVJJIGZvciAnICsgcHJvcE5hbWUgKyAnIGluICcgK1xuICAgKiAgICAgICAgICAgIGNvbXBvbmVudE5hbWVcbiAgICogICAgICAgICAgKTtcbiAgICogICAgICAgIH1cbiAgICogICAgICB9XG4gICAqICAgIH0sXG4gICAqICAgIHJlbmRlcjogZnVuY3Rpb24oKSB7Li4ufVxuICAgKiAgfSk7XG4gICAqXG4gICAqIEBpbnRlcm5hbFxuICAgKi9cblxuICB2YXIgQU5PTllNT1VTID0gJzw8YW5vbnltb3VzPj4nO1xuXG4gIC8vIEltcG9ydGFudCFcbiAgLy8gS2VlcCB0aGlzIGxpc3QgaW4gc3luYyB3aXRoIHByb2R1Y3Rpb24gdmVyc2lvbiBpbiBgLi9mYWN0b3J5V2l0aFRocm93aW5nU2hpbXMuanNgLlxuICB2YXIgUmVhY3RQcm9wVHlwZXMgPSB7XG4gICAgYXJyYXk6IGNyZWF0ZVByaW1pdGl2ZVR5cGVDaGVja2VyKCdhcnJheScpLFxuICAgIGJpZ2ludDogY3JlYXRlUHJpbWl0aXZlVHlwZUNoZWNrZXIoJ2JpZ2ludCcpLFxuICAgIGJvb2w6IGNyZWF0ZVByaW1pdGl2ZVR5cGVDaGVja2VyKCdib29sZWFuJyksXG4gICAgZnVuYzogY3JlYXRlUHJpbWl0aXZlVHlwZUNoZWNrZXIoJ2Z1bmN0aW9uJyksXG4gICAgbnVtYmVyOiBjcmVhdGVQcmltaXRpdmVUeXBlQ2hlY2tlcignbnVtYmVyJyksXG4gICAgb2JqZWN0OiBjcmVhdGVQcmltaXRpdmVUeXBlQ2hlY2tlcignb2JqZWN0JyksXG4gICAgc3RyaW5nOiBjcmVhdGVQcmltaXRpdmVUeXBlQ2hlY2tlcignc3RyaW5nJyksXG4gICAgc3ltYm9sOiBjcmVhdGVQcmltaXRpdmVUeXBlQ2hlY2tlcignc3ltYm9sJyksXG5cbiAgICBhbnk6IGNyZWF0ZUFueVR5cGVDaGVja2VyKCksXG4gICAgYXJyYXlPZjogY3JlYXRlQXJyYXlPZlR5cGVDaGVja2VyLFxuICAgIGVsZW1lbnQ6IGNyZWF0ZUVsZW1lbnRUeXBlQ2hlY2tlcigpLFxuICAgIGVsZW1lbnRUeXBlOiBjcmVhdGVFbGVtZW50VHlwZVR5cGVDaGVja2VyKCksXG4gICAgaW5zdGFuY2VPZjogY3JlYXRlSW5zdGFuY2VUeXBlQ2hlY2tlcixcbiAgICBub2RlOiBjcmVhdGVOb2RlQ2hlY2tlcigpLFxuICAgIG9iamVjdE9mOiBjcmVhdGVPYmplY3RPZlR5cGVDaGVja2VyLFxuICAgIG9uZU9mOiBjcmVhdGVFbnVtVHlwZUNoZWNrZXIsXG4gICAgb25lT2ZUeXBlOiBjcmVhdGVVbmlvblR5cGVDaGVja2VyLFxuICAgIHNoYXBlOiBjcmVhdGVTaGFwZVR5cGVDaGVja2VyLFxuICAgIGV4YWN0OiBjcmVhdGVTdHJpY3RTaGFwZVR5cGVDaGVja2VyLFxuICB9O1xuXG4gIC8qKlxuICAgKiBpbmxpbmVkIE9iamVjdC5pcyBwb2x5ZmlsbCB0byBhdm9pZCByZXF1aXJpbmcgY29uc3VtZXJzIHNoaXAgdGhlaXIgb3duXG4gICAqIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0phdmFTY3JpcHQvUmVmZXJlbmNlL0dsb2JhbF9PYmplY3RzL09iamVjdC9pc1xuICAgKi9cbiAgLyplc2xpbnQtZGlzYWJsZSBuby1zZWxmLWNvbXBhcmUqL1xuICBmdW5jdGlvbiBpcyh4LCB5KSB7XG4gICAgLy8gU2FtZVZhbHVlIGFsZ29yaXRobVxuICAgIGlmICh4ID09PSB5KSB7XG4gICAgICAvLyBTdGVwcyAxLTUsIDctMTBcbiAgICAgIC8vIFN0ZXBzIDYuYi02LmU6ICswICE9IC0wXG4gICAgICByZXR1cm4geCAhPT0gMCB8fCAxIC8geCA9PT0gMSAvIHk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFN0ZXAgNi5hOiBOYU4gPT0gTmFOXG4gICAgICByZXR1cm4geCAhPT0geCAmJiB5ICE9PSB5O1xuICAgIH1cbiAgfVxuICAvKmVzbGludC1lbmFibGUgbm8tc2VsZi1jb21wYXJlKi9cblxuICAvKipcbiAgICogV2UgdXNlIGFuIEVycm9yLWxpa2Ugb2JqZWN0IGZvciBiYWNrd2FyZCBjb21wYXRpYmlsaXR5IGFzIHBlb3BsZSBtYXkgY2FsbFxuICAgKiBQcm9wVHlwZXMgZGlyZWN0bHkgYW5kIGluc3BlY3QgdGhlaXIgb3V0cHV0LiBIb3dldmVyLCB3ZSBkb24ndCB1c2UgcmVhbFxuICAgKiBFcnJvcnMgYW55bW9yZS4gV2UgZG9uJ3QgaW5zcGVjdCB0aGVpciBzdGFjayBhbnl3YXksIGFuZCBjcmVhdGluZyB0aGVtXG4gICAqIGlzIHByb2hpYml0aXZlbHkgZXhwZW5zaXZlIGlmIHRoZXkgYXJlIGNyZWF0ZWQgdG9vIG9mdGVuLCBzdWNoIGFzIHdoYXRcbiAgICogaGFwcGVucyBpbiBvbmVPZlR5cGUoKSBmb3IgYW55IHR5cGUgYmVmb3JlIHRoZSBvbmUgdGhhdCBtYXRjaGVkLlxuICAgKi9cbiAgZnVuY3Rpb24gUHJvcFR5cGVFcnJvcihtZXNzYWdlLCBkYXRhKSB7XG4gICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICB0aGlzLmRhdGEgPSBkYXRhICYmIHR5cGVvZiBkYXRhID09PSAnb2JqZWN0JyA/IGRhdGE6IHt9O1xuICAgIHRoaXMuc3RhY2sgPSAnJztcbiAgfVxuICAvLyBNYWtlIGBpbnN0YW5jZW9mIEVycm9yYCBzdGlsbCB3b3JrIGZvciByZXR1cm5lZCBlcnJvcnMuXG4gIFByb3BUeXBlRXJyb3IucHJvdG90eXBlID0gRXJyb3IucHJvdG90eXBlO1xuXG4gIGZ1bmN0aW9uIGNyZWF0ZUNoYWluYWJsZVR5cGVDaGVja2VyKHZhbGlkYXRlKSB7XG4gICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicpIHtcbiAgICAgIHZhciBtYW51YWxQcm9wVHlwZUNhbGxDYWNoZSA9IHt9O1xuICAgICAgdmFyIG1hbnVhbFByb3BUeXBlV2FybmluZ0NvdW50ID0gMDtcbiAgICB9XG4gICAgZnVuY3Rpb24gY2hlY2tUeXBlKGlzUmVxdWlyZWQsIHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSwgc2VjcmV0KSB7XG4gICAgICBjb21wb25lbnROYW1lID0gY29tcG9uZW50TmFtZSB8fCBBTk9OWU1PVVM7XG4gICAgICBwcm9wRnVsbE5hbWUgPSBwcm9wRnVsbE5hbWUgfHwgcHJvcE5hbWU7XG5cbiAgICAgIGlmIChzZWNyZXQgIT09IFJlYWN0UHJvcFR5cGVzU2VjcmV0KSB7XG4gICAgICAgIGlmICh0aHJvd09uRGlyZWN0QWNjZXNzKSB7XG4gICAgICAgICAgLy8gTmV3IGJlaGF2aW9yIG9ubHkgZm9yIHVzZXJzIG9mIGBwcm9wLXR5cGVzYCBwYWNrYWdlXG4gICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcihcbiAgICAgICAgICAgICdDYWxsaW5nIFByb3BUeXBlcyB2YWxpZGF0b3JzIGRpcmVjdGx5IGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlIGBwcm9wLXR5cGVzYCBwYWNrYWdlLiAnICtcbiAgICAgICAgICAgICdVc2UgYFByb3BUeXBlcy5jaGVja1Byb3BUeXBlcygpYCB0byBjYWxsIHRoZW0uICcgK1xuICAgICAgICAgICAgJ1JlYWQgbW9yZSBhdCBodHRwOi8vZmIubWUvdXNlLWNoZWNrLXByb3AtdHlwZXMnXG4gICAgICAgICAgKTtcbiAgICAgICAgICBlcnIubmFtZSA9ICdJbnZhcmlhbnQgVmlvbGF0aW9uJztcbiAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH0gZWxzZSBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJyAmJiB0eXBlb2YgY29uc29sZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAvLyBPbGQgYmVoYXZpb3IgZm9yIHBlb3BsZSB1c2luZyBSZWFjdC5Qcm9wVHlwZXNcbiAgICAgICAgICB2YXIgY2FjaGVLZXkgPSBjb21wb25lbnROYW1lICsgJzonICsgcHJvcE5hbWU7XG4gICAgICAgICAgaWYgKFxuICAgICAgICAgICAgIW1hbnVhbFByb3BUeXBlQ2FsbENhY2hlW2NhY2hlS2V5XSAmJlxuICAgICAgICAgICAgLy8gQXZvaWQgc3BhbW1pbmcgdGhlIGNvbnNvbGUgYmVjYXVzZSB0aGV5IGFyZSBvZnRlbiBub3QgYWN0aW9uYWJsZSBleGNlcHQgZm9yIGxpYiBhdXRob3JzXG4gICAgICAgICAgICBtYW51YWxQcm9wVHlwZVdhcm5pbmdDb3VudCA8IDNcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgIHByaW50V2FybmluZyhcbiAgICAgICAgICAgICAgJ1lvdSBhcmUgbWFudWFsbHkgY2FsbGluZyBhIFJlYWN0LlByb3BUeXBlcyB2YWxpZGF0aW9uICcgK1xuICAgICAgICAgICAgICAnZnVuY3Rpb24gZm9yIHRoZSBgJyArIHByb3BGdWxsTmFtZSArICdgIHByb3Agb24gYCcgKyBjb21wb25lbnROYW1lICsgJ2AuIFRoaXMgaXMgZGVwcmVjYXRlZCAnICtcbiAgICAgICAgICAgICAgJ2FuZCB3aWxsIHRocm93IGluIHRoZSBzdGFuZGFsb25lIGBwcm9wLXR5cGVzYCBwYWNrYWdlLiAnICtcbiAgICAgICAgICAgICAgJ1lvdSBtYXkgYmUgc2VlaW5nIHRoaXMgd2FybmluZyBkdWUgdG8gYSB0aGlyZC1wYXJ0eSBQcm9wVHlwZXMgJyArXG4gICAgICAgICAgICAgICdsaWJyYXJ5LiBTZWUgaHR0cHM6Ly9mYi5tZS9yZWFjdC13YXJuaW5nLWRvbnQtY2FsbC1wcm9wdHlwZXMgJyArICdmb3IgZGV0YWlscy4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgbWFudWFsUHJvcFR5cGVDYWxsQ2FjaGVbY2FjaGVLZXldID0gdHJ1ZTtcbiAgICAgICAgICAgIG1hbnVhbFByb3BUeXBlV2FybmluZ0NvdW50Kys7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAocHJvcHNbcHJvcE5hbWVdID09IG51bGwpIHtcbiAgICAgICAgaWYgKGlzUmVxdWlyZWQpIHtcbiAgICAgICAgICBpZiAocHJvcHNbcHJvcE5hbWVdID09PSBudWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFByb3BUeXBlRXJyb3IoJ1RoZSAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2AgaXMgbWFya2VkIGFzIHJlcXVpcmVkICcgKyAoJ2luIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBidXQgaXRzIHZhbHVlIGlzIGBudWxsYC4nKSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignVGhlICcgKyBsb2NhdGlvbiArICcgYCcgKyBwcm9wRnVsbE5hbWUgKyAnYCBpcyBtYXJrZWQgYXMgcmVxdWlyZWQgaW4gJyArICgnYCcgKyBjb21wb25lbnROYW1lICsgJ2AsIGJ1dCBpdHMgdmFsdWUgaXMgYHVuZGVmaW5lZGAuJykpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIHZhbGlkYXRlKHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdmFyIGNoYWluZWRDaGVja1R5cGUgPSBjaGVja1R5cGUuYmluZChudWxsLCBmYWxzZSk7XG4gICAgY2hhaW5lZENoZWNrVHlwZS5pc1JlcXVpcmVkID0gY2hlY2tUeXBlLmJpbmQobnVsbCwgdHJ1ZSk7XG5cbiAgICByZXR1cm4gY2hhaW5lZENoZWNrVHlwZTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNyZWF0ZVByaW1pdGl2ZVR5cGVDaGVja2VyKGV4cGVjdGVkVHlwZSkge1xuICAgIGZ1bmN0aW9uIHZhbGlkYXRlKHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSwgc2VjcmV0KSB7XG4gICAgICB2YXIgcHJvcFZhbHVlID0gcHJvcHNbcHJvcE5hbWVdO1xuICAgICAgdmFyIHByb3BUeXBlID0gZ2V0UHJvcFR5cGUocHJvcFZhbHVlKTtcbiAgICAgIGlmIChwcm9wVHlwZSAhPT0gZXhwZWN0ZWRUeXBlKSB7XG4gICAgICAgIC8vIGBwcm9wVmFsdWVgIGJlaW5nIGluc3RhbmNlIG9mLCBzYXksIGRhdGUvcmVnZXhwLCBwYXNzIHRoZSAnb2JqZWN0J1xuICAgICAgICAvLyBjaGVjaywgYnV0IHdlIGNhbiBvZmZlciBhIG1vcmUgcHJlY2lzZSBlcnJvciBtZXNzYWdlIGhlcmUgcmF0aGVyIHRoYW5cbiAgICAgICAgLy8gJ29mIHR5cGUgYG9iamVjdGAnLlxuICAgICAgICB2YXIgcHJlY2lzZVR5cGUgPSBnZXRQcmVjaXNlVHlwZShwcm9wVmFsdWUpO1xuXG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcihcbiAgICAgICAgICAnSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgdHlwZSAnICsgKCdgJyArIHByZWNpc2VUeXBlICsgJ2Agc3VwcGxpZWQgdG8gYCcgKyBjb21wb25lbnROYW1lICsgJ2AsIGV4cGVjdGVkICcpICsgKCdgJyArIGV4cGVjdGVkVHlwZSArICdgLicpLFxuICAgICAgICAgIHtleHBlY3RlZFR5cGU6IGV4cGVjdGVkVHlwZX1cbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlQW55VHlwZUNoZWNrZXIoKSB7XG4gICAgcmV0dXJuIGNyZWF0ZUNoYWluYWJsZVR5cGVDaGVja2VyKGVtcHR5RnVuY3Rpb25UaGF0UmV0dXJuc051bGwpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlQXJyYXlPZlR5cGVDaGVja2VyKHR5cGVDaGVja2VyKSB7XG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICBpZiAodHlwZW9mIHR5cGVDaGVja2VyICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignUHJvcGVydHkgYCcgKyBwcm9wRnVsbE5hbWUgKyAnYCBvZiBjb21wb25lbnQgYCcgKyBjb21wb25lbnROYW1lICsgJ2AgaGFzIGludmFsaWQgUHJvcFR5cGUgbm90YXRpb24gaW5zaWRlIGFycmF5T2YuJyk7XG4gICAgICB9XG4gICAgICB2YXIgcHJvcFZhbHVlID0gcHJvcHNbcHJvcE5hbWVdO1xuICAgICAgaWYgKCFBcnJheS5pc0FycmF5KHByb3BWYWx1ZSkpIHtcbiAgICAgICAgdmFyIHByb3BUeXBlID0gZ2V0UHJvcFR5cGUocHJvcFZhbHVlKTtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9wVHlwZUVycm9yKCdJbnZhbGlkICcgKyBsb2NhdGlvbiArICcgYCcgKyBwcm9wRnVsbE5hbWUgKyAnYCBvZiB0eXBlICcgKyAoJ2AnICsgcHJvcFR5cGUgKyAnYCBzdXBwbGllZCB0byBgJyArIGNvbXBvbmVudE5hbWUgKyAnYCwgZXhwZWN0ZWQgYW4gYXJyYXkuJykpO1xuICAgICAgfVxuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBwcm9wVmFsdWUubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdmFyIGVycm9yID0gdHlwZUNoZWNrZXIocHJvcFZhbHVlLCBpLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lICsgJ1snICsgaSArICddJywgUmVhY3RQcm9wVHlwZXNTZWNyZXQpO1xuICAgICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICAgIHJldHVybiBlcnJvcjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBjcmVhdGVDaGFpbmFibGVUeXBlQ2hlY2tlcih2YWxpZGF0ZSk7XG4gIH1cblxuICBmdW5jdGlvbiBjcmVhdGVFbGVtZW50VHlwZUNoZWNrZXIoKSB7XG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICB2YXIgcHJvcFZhbHVlID0gcHJvcHNbcHJvcE5hbWVdO1xuICAgICAgaWYgKCFpc1ZhbGlkRWxlbWVudChwcm9wVmFsdWUpKSB7XG4gICAgICAgIHZhciBwcm9wVHlwZSA9IGdldFByb3BUeXBlKHByb3BWYWx1ZSk7XG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgdHlwZSAnICsgKCdgJyArIHByb3BUeXBlICsgJ2Agc3VwcGxpZWQgdG8gYCcgKyBjb21wb25lbnROYW1lICsgJ2AsIGV4cGVjdGVkIGEgc2luZ2xlIFJlYWN0RWxlbWVudC4nKSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIGNyZWF0ZUNoYWluYWJsZVR5cGVDaGVja2VyKHZhbGlkYXRlKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNyZWF0ZUVsZW1lbnRUeXBlVHlwZUNoZWNrZXIoKSB7XG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICB2YXIgcHJvcFZhbHVlID0gcHJvcHNbcHJvcE5hbWVdO1xuICAgICAgaWYgKCFSZWFjdElzLmlzVmFsaWRFbGVtZW50VHlwZShwcm9wVmFsdWUpKSB7XG4gICAgICAgIHZhciBwcm9wVHlwZSA9IGdldFByb3BUeXBlKHByb3BWYWx1ZSk7XG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgdHlwZSAnICsgKCdgJyArIHByb3BUeXBlICsgJ2Agc3VwcGxpZWQgdG8gYCcgKyBjb21wb25lbnROYW1lICsgJ2AsIGV4cGVjdGVkIGEgc2luZ2xlIFJlYWN0RWxlbWVudCB0eXBlLicpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlSW5zdGFuY2VUeXBlQ2hlY2tlcihleHBlY3RlZENsYXNzKSB7XG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICBpZiAoIShwcm9wc1twcm9wTmFtZV0gaW5zdGFuY2VvZiBleHBlY3RlZENsYXNzKSkge1xuICAgICAgICB2YXIgZXhwZWN0ZWRDbGFzc05hbWUgPSBleHBlY3RlZENsYXNzLm5hbWUgfHwgQU5PTllNT1VTO1xuICAgICAgICB2YXIgYWN0dWFsQ2xhc3NOYW1lID0gZ2V0Q2xhc3NOYW1lKHByb3BzW3Byb3BOYW1lXSk7XG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgdHlwZSAnICsgKCdgJyArIGFjdHVhbENsYXNzTmFtZSArICdgIHN1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBleHBlY3RlZCAnKSArICgnaW5zdGFuY2Ugb2YgYCcgKyBleHBlY3RlZENsYXNzTmFtZSArICdgLicpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlRW51bVR5cGVDaGVja2VyKGV4cGVjdGVkVmFsdWVzKSB7XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGV4cGVjdGVkVmFsdWVzKSkge1xuICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicpIHtcbiAgICAgICAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPiAxKSB7XG4gICAgICAgICAgcHJpbnRXYXJuaW5nKFxuICAgICAgICAgICAgJ0ludmFsaWQgYXJndW1lbnRzIHN1cHBsaWVkIHRvIG9uZU9mLCBleHBlY3RlZCBhbiBhcnJheSwgZ290ICcgKyBhcmd1bWVudHMubGVuZ3RoICsgJyBhcmd1bWVudHMuICcgK1xuICAgICAgICAgICAgJ0EgY29tbW9uIG1pc3Rha2UgaXMgdG8gd3JpdGUgb25lT2YoeCwgeSwgeikgaW5zdGVhZCBvZiBvbmVPZihbeCwgeSwgel0pLidcbiAgICAgICAgICApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHByaW50V2FybmluZygnSW52YWxpZCBhcmd1bWVudCBzdXBwbGllZCB0byBvbmVPZiwgZXhwZWN0ZWQgYW4gYXJyYXkuJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBlbXB0eUZ1bmN0aW9uVGhhdFJldHVybnNOdWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZhbGlkYXRlKHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSkge1xuICAgICAgdmFyIHByb3BWYWx1ZSA9IHByb3BzW3Byb3BOYW1lXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXhwZWN0ZWRWYWx1ZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgaWYgKGlzKHByb3BWYWx1ZSwgZXhwZWN0ZWRWYWx1ZXNbaV0pKSB7XG4gICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgdmFyIHZhbHVlc1N0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV4cGVjdGVkVmFsdWVzLCBmdW5jdGlvbiByZXBsYWNlcihrZXksIHZhbHVlKSB7XG4gICAgICAgIHZhciB0eXBlID0gZ2V0UHJlY2lzZVR5cGUodmFsdWUpO1xuICAgICAgICBpZiAodHlwZSA9PT0gJ3N5bWJvbCcpIHtcbiAgICAgICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgICB9KTtcbiAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgdmFsdWUgYCcgKyBTdHJpbmcocHJvcFZhbHVlKSArICdgICcgKyAoJ3N1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBleHBlY3RlZCBvbmUgb2YgJyArIHZhbHVlc1N0cmluZyArICcuJykpO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlT2JqZWN0T2ZUeXBlQ2hlY2tlcih0eXBlQ2hlY2tlcikge1xuICAgIGZ1bmN0aW9uIHZhbGlkYXRlKHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSkge1xuICAgICAgaWYgKHR5cGVvZiB0eXBlQ2hlY2tlciAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4gbmV3IFByb3BUeXBlRXJyb3IoJ1Byb3BlcnR5IGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agb2YgY29tcG9uZW50IGAnICsgY29tcG9uZW50TmFtZSArICdgIGhhcyBpbnZhbGlkIFByb3BUeXBlIG5vdGF0aW9uIGluc2lkZSBvYmplY3RPZi4nKTtcbiAgICAgIH1cbiAgICAgIHZhciBwcm9wVmFsdWUgPSBwcm9wc1twcm9wTmFtZV07XG4gICAgICB2YXIgcHJvcFR5cGUgPSBnZXRQcm9wVHlwZShwcm9wVmFsdWUpO1xuICAgICAgaWYgKHByb3BUeXBlICE9PSAnb2JqZWN0Jykge1xuICAgICAgICByZXR1cm4gbmV3IFByb3BUeXBlRXJyb3IoJ0ludmFsaWQgJyArIGxvY2F0aW9uICsgJyBgJyArIHByb3BGdWxsTmFtZSArICdgIG9mIHR5cGUgJyArICgnYCcgKyBwcm9wVHlwZSArICdgIHN1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBleHBlY3RlZCBhbiBvYmplY3QuJykpO1xuICAgICAgfVxuICAgICAgZm9yICh2YXIga2V5IGluIHByb3BWYWx1ZSkge1xuICAgICAgICBpZiAoaGFzKHByb3BWYWx1ZSwga2V5KSkge1xuICAgICAgICAgIHZhciBlcnJvciA9IHR5cGVDaGVja2VyKHByb3BWYWx1ZSwga2V5LCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lICsgJy4nICsga2V5LCBSZWFjdFByb3BUeXBlc1NlY3JldCk7XG4gICAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIHJldHVybiBlcnJvcjtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlVW5pb25UeXBlQ2hlY2tlcihhcnJheU9mVHlwZUNoZWNrZXJzKSB7XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGFycmF5T2ZUeXBlQ2hlY2tlcnMpKSB7XG4gICAgICBwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nID8gcHJpbnRXYXJuaW5nKCdJbnZhbGlkIGFyZ3VtZW50IHN1cHBsaWVkIHRvIG9uZU9mVHlwZSwgZXhwZWN0ZWQgYW4gaW5zdGFuY2Ugb2YgYXJyYXkuJykgOiB2b2lkIDA7XG4gICAgICByZXR1cm4gZW1wdHlGdW5jdGlvblRoYXRSZXR1cm5zTnVsbDtcbiAgICB9XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFycmF5T2ZUeXBlQ2hlY2tlcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBjaGVja2VyID0gYXJyYXlPZlR5cGVDaGVja2Vyc1tpXTtcbiAgICAgIGlmICh0eXBlb2YgY2hlY2tlciAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBwcmludFdhcm5pbmcoXG4gICAgICAgICAgJ0ludmFsaWQgYXJndW1lbnQgc3VwcGxpZWQgdG8gb25lT2ZUeXBlLiBFeHBlY3RlZCBhbiBhcnJheSBvZiBjaGVjayBmdW5jdGlvbnMsIGJ1dCAnICtcbiAgICAgICAgICAncmVjZWl2ZWQgJyArIGdldFBvc3RmaXhGb3JUeXBlV2FybmluZyhjaGVja2VyKSArICcgYXQgaW5kZXggJyArIGkgKyAnLidcbiAgICAgICAgKTtcbiAgICAgICAgcmV0dXJuIGVtcHR5RnVuY3Rpb25UaGF0UmV0dXJuc051bGw7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICB2YXIgZXhwZWN0ZWRUeXBlcyA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcnJheU9mVHlwZUNoZWNrZXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciBjaGVja2VyID0gYXJyYXlPZlR5cGVDaGVja2Vyc1tpXTtcbiAgICAgICAgdmFyIGNoZWNrZXJSZXN1bHQgPSBjaGVja2VyKHByb3BzLCBwcm9wTmFtZSwgY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSwgUmVhY3RQcm9wVHlwZXNTZWNyZXQpO1xuICAgICAgICBpZiAoY2hlY2tlclJlc3VsdCA9PSBudWxsKSB7XG4gICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGNoZWNrZXJSZXN1bHQuZGF0YSAmJiBoYXMoY2hlY2tlclJlc3VsdC5kYXRhLCAnZXhwZWN0ZWRUeXBlJykpIHtcbiAgICAgICAgICBleHBlY3RlZFR5cGVzLnB1c2goY2hlY2tlclJlc3VsdC5kYXRhLmV4cGVjdGVkVHlwZSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHZhciBleHBlY3RlZFR5cGVzTWVzc2FnZSA9IChleHBlY3RlZFR5cGVzLmxlbmd0aCA+IDApID8gJywgZXhwZWN0ZWQgb25lIG9mIHR5cGUgWycgKyBleHBlY3RlZFR5cGVzLmpvaW4oJywgJykgKyAnXSc6ICcnO1xuICAgICAgcmV0dXJuIG5ldyBQcm9wVHlwZUVycm9yKCdJbnZhbGlkICcgKyBsb2NhdGlvbiArICcgYCcgKyBwcm9wRnVsbE5hbWUgKyAnYCBzdXBwbGllZCB0byAnICsgKCdgJyArIGNvbXBvbmVudE5hbWUgKyAnYCcgKyBleHBlY3RlZFR5cGVzTWVzc2FnZSArICcuJykpO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gY3JlYXRlTm9kZUNoZWNrZXIoKSB7XG4gICAgZnVuY3Rpb24gdmFsaWRhdGUocHJvcHMsIHByb3BOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lKSB7XG4gICAgICBpZiAoIWlzTm9kZShwcm9wc1twcm9wTmFtZV0pKSB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcignSW52YWxpZCAnICsgbG9jYXRpb24gKyAnIGAnICsgcHJvcEZ1bGxOYW1lICsgJ2Agc3VwcGxpZWQgdG8gJyArICgnYCcgKyBjb21wb25lbnROYW1lICsgJ2AsIGV4cGVjdGVkIGEgUmVhY3ROb2RlLicpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gY3JlYXRlQ2hhaW5hYmxlVHlwZUNoZWNrZXIodmFsaWRhdGUpO1xuICB9XG5cbiAgZnVuY3Rpb24gaW52YWxpZFZhbGlkYXRvckVycm9yKGNvbXBvbmVudE5hbWUsIGxvY2F0aW9uLCBwcm9wRnVsbE5hbWUsIGtleSwgdHlwZSkge1xuICAgIHJldHVybiBuZXcgUHJvcFR5cGVFcnJvcihcbiAgICAgIChjb21wb25lbnROYW1lIHx8ICdSZWFjdCBjbGFzcycpICsgJzogJyArIGxvY2F0aW9uICsgJyB0eXBlIGAnICsgcHJvcEZ1bGxOYW1lICsgJy4nICsga2V5ICsgJ2AgaXMgaW52YWxpZDsgJyArXG4gICAgICAnaXQgbXVzdCBiZSBhIGZ1bmN0aW9uLCB1c3VhbGx5IGZyb20gdGhlIGBwcm9wLXR5cGVzYCBwYWNrYWdlLCBidXQgcmVjZWl2ZWQgYCcgKyB0eXBlICsgJ2AuJ1xuICAgICk7XG4gIH1cblxuICBmdW5jdGlvbiBjcmVhdGVTaGFwZVR5cGVDaGVja2VyKHNoYXBlVHlwZXMpIHtcbiAgICBmdW5jdGlvbiB2YWxpZGF0ZShwcm9wcywgcHJvcE5hbWUsIGNvbXBvbmVudE5hbWUsIGxvY2F0aW9uLCBwcm9wRnVsbE5hbWUpIHtcbiAgICAgIHZhciBwcm9wVmFsdWUgPSBwcm9wc1twcm9wTmFtZV07XG4gICAgICB2YXIgcHJvcFR5cGUgPSBnZXRQcm9wVHlwZShwcm9wVmFsdWUpO1xuICAgICAgaWYgKHByb3BUeXBlICE9PSAnb2JqZWN0Jykge1xuICAgICAgICByZXR1cm4gbmV3IFByb3BUeXBlRXJyb3IoJ0ludmFsaWQgJyArIGxvY2F0aW9uICsgJyBgJyArIHByb3BGdWxsTmFtZSArICdgIG9mIHR5cGUgYCcgKyBwcm9wVHlwZSArICdgICcgKyAoJ3N1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBleHBlY3RlZCBgb2JqZWN0YC4nKSk7XG4gICAgICB9XG4gICAgICBmb3IgKHZhciBrZXkgaW4gc2hhcGVUeXBlcykge1xuICAgICAgICB2YXIgY2hlY2tlciA9IHNoYXBlVHlwZXNba2V5XTtcbiAgICAgICAgaWYgKHR5cGVvZiBjaGVja2VyICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgcmV0dXJuIGludmFsaWRWYWxpZGF0b3JFcnJvcihjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lLCBrZXksIGdldFByZWNpc2VUeXBlKGNoZWNrZXIpKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgZXJyb3IgPSBjaGVja2VyKHByb3BWYWx1ZSwga2V5LCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lICsgJy4nICsga2V5LCBSZWFjdFByb3BUeXBlc1NlY3JldCk7XG4gICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgIHJldHVybiBlcnJvcjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBjcmVhdGVDaGFpbmFibGVUeXBlQ2hlY2tlcih2YWxpZGF0ZSk7XG4gIH1cblxuICBmdW5jdGlvbiBjcmVhdGVTdHJpY3RTaGFwZVR5cGVDaGVja2VyKHNoYXBlVHlwZXMpIHtcbiAgICBmdW5jdGlvbiB2YWxpZGF0ZShwcm9wcywgcHJvcE5hbWUsIGNvbXBvbmVudE5hbWUsIGxvY2F0aW9uLCBwcm9wRnVsbE5hbWUpIHtcbiAgICAgIHZhciBwcm9wVmFsdWUgPSBwcm9wc1twcm9wTmFtZV07XG4gICAgICB2YXIgcHJvcFR5cGUgPSBnZXRQcm9wVHlwZShwcm9wVmFsdWUpO1xuICAgICAgaWYgKHByb3BUeXBlICE9PSAnb2JqZWN0Jykge1xuICAgICAgICByZXR1cm4gbmV3IFByb3BUeXBlRXJyb3IoJ0ludmFsaWQgJyArIGxvY2F0aW9uICsgJyBgJyArIHByb3BGdWxsTmFtZSArICdgIG9mIHR5cGUgYCcgKyBwcm9wVHlwZSArICdgICcgKyAoJ3N1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLCBleHBlY3RlZCBgb2JqZWN0YC4nKSk7XG4gICAgICB9XG4gICAgICAvLyBXZSBuZWVkIHRvIGNoZWNrIGFsbCBrZXlzIGluIGNhc2Ugc29tZSBhcmUgcmVxdWlyZWQgYnV0IG1pc3NpbmcgZnJvbSBwcm9wcy5cbiAgICAgIHZhciBhbGxLZXlzID0gYXNzaWduKHt9LCBwcm9wc1twcm9wTmFtZV0sIHNoYXBlVHlwZXMpO1xuICAgICAgZm9yICh2YXIga2V5IGluIGFsbEtleXMpIHtcbiAgICAgICAgdmFyIGNoZWNrZXIgPSBzaGFwZVR5cGVzW2tleV07XG4gICAgICAgIGlmIChoYXMoc2hhcGVUeXBlcywga2V5KSAmJiB0eXBlb2YgY2hlY2tlciAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgIHJldHVybiBpbnZhbGlkVmFsaWRhdG9yRXJyb3IoY29tcG9uZW50TmFtZSwgbG9jYXRpb24sIHByb3BGdWxsTmFtZSwga2V5LCBnZXRQcmVjaXNlVHlwZShjaGVja2VyKSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFjaGVja2VyKSB7XG4gICAgICAgICAgcmV0dXJuIG5ldyBQcm9wVHlwZUVycm9yKFxuICAgICAgICAgICAgJ0ludmFsaWQgJyArIGxvY2F0aW9uICsgJyBgJyArIHByb3BGdWxsTmFtZSArICdgIGtleSBgJyArIGtleSArICdgIHN1cHBsaWVkIHRvIGAnICsgY29tcG9uZW50TmFtZSArICdgLicgK1xuICAgICAgICAgICAgJ1xcbkJhZCBvYmplY3Q6ICcgKyBKU09OLnN0cmluZ2lmeShwcm9wc1twcm9wTmFtZV0sIG51bGwsICcgICcpICtcbiAgICAgICAgICAgICdcXG5WYWxpZCBrZXlzOiAnICsgSlNPTi5zdHJpbmdpZnkoT2JqZWN0LmtleXMoc2hhcGVUeXBlcyksIG51bGwsICcgICcpXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgZXJyb3IgPSBjaGVja2VyKHByb3BWYWx1ZSwga2V5LCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgcHJvcEZ1bGxOYW1lICsgJy4nICsga2V5LCBSZWFjdFByb3BUeXBlc1NlY3JldCk7XG4gICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgIHJldHVybiBlcnJvcjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuXG4gICAgcmV0dXJuIGNyZWF0ZUNoYWluYWJsZVR5cGVDaGVja2VyKHZhbGlkYXRlKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGlzTm9kZShwcm9wVmFsdWUpIHtcbiAgICBzd2l0Y2ggKHR5cGVvZiBwcm9wVmFsdWUpIHtcbiAgICAgIGNhc2UgJ251bWJlcic6XG4gICAgICBjYXNlICdzdHJpbmcnOlxuICAgICAgY2FzZSAndW5kZWZpbmVkJzpcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICBjYXNlICdib29sZWFuJzpcbiAgICAgICAgcmV0dXJuICFwcm9wVmFsdWU7XG4gICAgICBjYXNlICdvYmplY3QnOlxuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShwcm9wVmFsdWUpKSB7XG4gICAgICAgICAgcmV0dXJuIHByb3BWYWx1ZS5ldmVyeShpc05vZGUpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChwcm9wVmFsdWUgPT09IG51bGwgfHwgaXNWYWxpZEVsZW1lbnQocHJvcFZhbHVlKSkge1xuICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgdmFyIGl0ZXJhdG9yRm4gPSBnZXRJdGVyYXRvckZuKHByb3BWYWx1ZSk7XG4gICAgICAgIGlmIChpdGVyYXRvckZuKSB7XG4gICAgICAgICAgdmFyIGl0ZXJhdG9yID0gaXRlcmF0b3JGbi5jYWxsKHByb3BWYWx1ZSk7XG4gICAgICAgICAgdmFyIHN0ZXA7XG4gICAgICAgICAgaWYgKGl0ZXJhdG9yRm4gIT09IHByb3BWYWx1ZS5lbnRyaWVzKSB7XG4gICAgICAgICAgICB3aGlsZSAoIShzdGVwID0gaXRlcmF0b3IubmV4dCgpKS5kb25lKSB7XG4gICAgICAgICAgICAgIGlmICghaXNOb2RlKHN0ZXAudmFsdWUpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIEl0ZXJhdG9yIHdpbGwgcHJvdmlkZSBlbnRyeSBbayx2XSB0dXBsZXMgcmF0aGVyIHRoYW4gdmFsdWVzLlxuICAgICAgICAgICAgd2hpbGUgKCEoc3RlcCA9IGl0ZXJhdG9yLm5leHQoKSkuZG9uZSkge1xuICAgICAgICAgICAgICB2YXIgZW50cnkgPSBzdGVwLnZhbHVlO1xuICAgICAgICAgICAgICBpZiAoZW50cnkpIHtcbiAgICAgICAgICAgICAgICBpZiAoIWlzTm9kZShlbnRyeVsxXSkpIHtcbiAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gaXNTeW1ib2wocHJvcFR5cGUsIHByb3BWYWx1ZSkge1xuICAgIC8vIE5hdGl2ZSBTeW1ib2wuXG4gICAgaWYgKHByb3BUeXBlID09PSAnc3ltYm9sJykge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgLy8gZmFsc3kgdmFsdWUgY2FuJ3QgYmUgYSBTeW1ib2xcbiAgICBpZiAoIXByb3BWYWx1ZSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8vIDE5LjQuMy41IFN5bWJvbC5wcm90b3R5cGVbQEB0b1N0cmluZ1RhZ10gPT09ICdTeW1ib2wnXG4gICAgaWYgKHByb3BWYWx1ZVsnQEB0b1N0cmluZ1RhZyddID09PSAnU3ltYm9sJykge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgLy8gRmFsbGJhY2sgZm9yIG5vbi1zcGVjIGNvbXBsaWFudCBTeW1ib2xzIHdoaWNoIGFyZSBwb2x5ZmlsbGVkLlxuICAgIGlmICh0eXBlb2YgU3ltYm9sID09PSAnZnVuY3Rpb24nICYmIHByb3BWYWx1ZSBpbnN0YW5jZW9mIFN5bWJvbCkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gRXF1aXZhbGVudCBvZiBgdHlwZW9mYCBidXQgd2l0aCBzcGVjaWFsIGhhbmRsaW5nIGZvciBhcnJheSBhbmQgcmVnZXhwLlxuICBmdW5jdGlvbiBnZXRQcm9wVHlwZShwcm9wVmFsdWUpIHtcbiAgICB2YXIgcHJvcFR5cGUgPSB0eXBlb2YgcHJvcFZhbHVlO1xuICAgIGlmIChBcnJheS5pc0FycmF5KHByb3BWYWx1ZSkpIHtcbiAgICAgIHJldHVybiAnYXJyYXknO1xuICAgIH1cbiAgICBpZiAocHJvcFZhbHVlIGluc3RhbmNlb2YgUmVnRXhwKSB7XG4gICAgICAvLyBPbGQgd2Via2l0cyAoYXQgbGVhc3QgdW50aWwgQW5kcm9pZCA0LjApIHJldHVybiAnZnVuY3Rpb24nIHJhdGhlciB0aGFuXG4gICAgICAvLyAnb2JqZWN0JyBmb3IgdHlwZW9mIGEgUmVnRXhwLiBXZSdsbCBub3JtYWxpemUgdGhpcyBoZXJlIHNvIHRoYXQgL2JsYS9cbiAgICAgIC8vIHBhc3NlcyBQcm9wVHlwZXMub2JqZWN0LlxuICAgICAgcmV0dXJuICdvYmplY3QnO1xuICAgIH1cbiAgICBpZiAoaXNTeW1ib2wocHJvcFR5cGUsIHByb3BWYWx1ZSkpIHtcbiAgICAgIHJldHVybiAnc3ltYm9sJztcbiAgICB9XG4gICAgcmV0dXJuIHByb3BUeXBlO1xuICB9XG5cbiAgLy8gVGhpcyBoYW5kbGVzIG1vcmUgdHlwZXMgdGhhbiBgZ2V0UHJvcFR5cGVgLiBPbmx5IHVzZWQgZm9yIGVycm9yIG1lc3NhZ2VzLlxuICAvLyBTZWUgYGNyZWF0ZVByaW1pdGl2ZVR5cGVDaGVja2VyYC5cbiAgZnVuY3Rpb24gZ2V0UHJlY2lzZVR5cGUocHJvcFZhbHVlKSB7XG4gICAgaWYgKHR5cGVvZiBwcm9wVmFsdWUgPT09ICd1bmRlZmluZWQnIHx8IHByb3BWYWx1ZSA9PT0gbnVsbCkge1xuICAgICAgcmV0dXJuICcnICsgcHJvcFZhbHVlO1xuICAgIH1cbiAgICB2YXIgcHJvcFR5cGUgPSBnZXRQcm9wVHlwZShwcm9wVmFsdWUpO1xuICAgIGlmIChwcm9wVHlwZSA9PT0gJ29iamVjdCcpIHtcbiAgICAgIGlmIChwcm9wVmFsdWUgaW5zdGFuY2VvZiBEYXRlKSB7XG4gICAgICAgIHJldHVybiAnZGF0ZSc7XG4gICAgICB9IGVsc2UgaWYgKHByb3BWYWx1ZSBpbnN0YW5jZW9mIFJlZ0V4cCkge1xuICAgICAgICByZXR1cm4gJ3JlZ2V4cCc7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBwcm9wVHlwZTtcbiAgfVxuXG4gIC8vIFJldHVybnMgYSBzdHJpbmcgdGhhdCBpcyBwb3N0Zml4ZWQgdG8gYSB3YXJuaW5nIGFib3V0IGFuIGludmFsaWQgdHlwZS5cbiAgLy8gRm9yIGV4YW1wbGUsIFwidW5kZWZpbmVkXCIgb3IgXCJvZiB0eXBlIGFycmF5XCJcbiAgZnVuY3Rpb24gZ2V0UG9zdGZpeEZvclR5cGVXYXJuaW5nKHZhbHVlKSB7XG4gICAgdmFyIHR5cGUgPSBnZXRQcmVjaXNlVHlwZSh2YWx1ZSk7XG4gICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICBjYXNlICdhcnJheSc6XG4gICAgICBjYXNlICdvYmplY3QnOlxuICAgICAgICByZXR1cm4gJ2FuICcgKyB0eXBlO1xuICAgICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICBjYXNlICdkYXRlJzpcbiAgICAgIGNhc2UgJ3JlZ2V4cCc6XG4gICAgICAgIHJldHVybiAnYSAnICsgdHlwZTtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiB0eXBlO1xuICAgIH1cbiAgfVxuXG4gIC8vIFJldHVybnMgY2xhc3MgbmFtZSBvZiB0aGUgb2JqZWN0LCBpZiBhbnkuXG4gIGZ1bmN0aW9uIGdldENsYXNzTmFtZShwcm9wVmFsdWUpIHtcbiAgICBpZiAoIXByb3BWYWx1ZS5jb25zdHJ1Y3RvciB8fCAhcHJvcFZhbHVlLmNvbnN0cnVjdG9yLm5hbWUpIHtcbiAgICAgIHJldHVybiBBTk9OWU1PVVM7XG4gICAgfVxuICAgIHJldHVybiBwcm9wVmFsdWUuY29uc3RydWN0b3IubmFtZTtcbiAgfVxuXG4gIFJlYWN0UHJvcFR5cGVzLmNoZWNrUHJvcFR5cGVzID0gY2hlY2tQcm9wVHlwZXM7XG4gIFJlYWN0UHJvcFR5cGVzLnJlc2V0V2FybmluZ0NhY2hlID0gY2hlY2tQcm9wVHlwZXMucmVzZXRXYXJuaW5nQ2FjaGU7XG4gIFJlYWN0UHJvcFR5cGVzLlByb3BUeXBlcyA9IFJlYWN0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
}).call(this,require("Xp6JUx"))
},{"./checkPropTypes":3,"./lib/ReactPropTypesSecret":7,"./lib/has":8,"Xp6JUx":2,"object-assign":1,"react-is":11}],6:[function(require,module,exports){
(function (process){
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

if (process.env.NODE_ENV !== 'production') {
  var ReactIs = require('react-is');

  // By explicitly using `prop-types` you are opting into new development behavior.
  // http://fb.me/prop-types-in-prod
  var throwOnDirectAccess = true;
  module.exports = require('./factoryWithTypeCheckers')(ReactIs.isElement, throwOnDirectAccess);
} else {
  // By explicitly using `prop-types` you are opting into new production behavior.
  // http://fb.me/prop-types-in-prod
  module.exports = require('./factoryWithThrowingShims')();
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJSZWFjdElzIiwicmVxdWlyZSIsInRocm93T25EaXJlY3RBY2Nlc3MiLCJtb2R1bGUiLCJleHBvcnRzIiwiaXNFbGVtZW50Il0sInNvdXJjZXMiOlsiaW5kZXguanMiXSwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTMtcHJlc2VudCwgRmFjZWJvb2ssIEluYy5cbiAqXG4gKiBUaGlzIHNvdXJjZSBjb2RlIGlzIGxpY2Vuc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZSBmb3VuZCBpbiB0aGVcbiAqIExJQ0VOU0UgZmlsZSBpbiB0aGUgcm9vdCBkaXJlY3Rvcnkgb2YgdGhpcyBzb3VyY2UgdHJlZS5cbiAqL1xuXG5pZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJykge1xuICB2YXIgUmVhY3RJcyA9IHJlcXVpcmUoJ3JlYWN0LWlzJyk7XG5cbiAgLy8gQnkgZXhwbGljaXRseSB1c2luZyBgcHJvcC10eXBlc2AgeW91IGFyZSBvcHRpbmcgaW50byBuZXcgZGV2ZWxvcG1lbnQgYmVoYXZpb3IuXG4gIC8vIGh0dHA6Ly9mYi5tZS9wcm9wLXR5cGVzLWluLXByb2RcbiAgdmFyIHRocm93T25EaXJlY3RBY2Nlc3MgPSB0cnVlO1xuICBtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4vZmFjdG9yeVdpdGhUeXBlQ2hlY2tlcnMnKShSZWFjdElzLmlzRWxlbWVudCwgdGhyb3dPbkRpcmVjdEFjY2Vzcyk7XG59IGVsc2Uge1xuICAvLyBCeSBleHBsaWNpdGx5IHVzaW5nIGBwcm9wLXR5cGVzYCB5b3UgYXJlIG9wdGluZyBpbnRvIG5ldyBwcm9kdWN0aW9uIGJlaGF2aW9yLlxuICAvLyBodHRwOi8vZmIubWUvcHJvcC10eXBlcy1pbi1wcm9kXG4gIG1vZHVsZS5leHBvcnRzID0gcmVxdWlyZSgnLi9mYWN0b3J5V2l0aFRocm93aW5nU2hpbXMnKSgpO1xufVxuIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUEsSUFBSUEsT0FBTyxDQUFDQyxHQUFHLENBQUNDLFFBQVEsS0FBSyxZQUFZLEVBQUU7RUFDekMsSUFBSUMsT0FBTyxHQUFHQyxPQUFPLENBQUMsVUFBVSxDQUFDOztFQUVqQztFQUNBO0VBQ0EsSUFBSUMsbUJBQW1CLEdBQUcsSUFBSTtFQUM5QkMsTUFBTSxDQUFDQyxPQUFPLEdBQUdILE9BQU8sQ0FBQywyQkFBMkIsQ0FBQyxDQUFDRCxPQUFPLENBQUNLLFNBQVMsRUFBRUgsbUJBQW1CLENBQUM7QUFDL0YsQ0FBQyxNQUFNO0VBQ0w7RUFDQTtFQUNBQyxNQUFNLENBQUNDLE9BQU8sR0FBR0gsT0FBTyxDQUFDLDRCQUE0QixDQUFDLEVBQUU7QUFDMUQifQ==
}).call(this,require("Xp6JUx"))
},{"./factoryWithThrowingShims":4,"./factoryWithTypeCheckers":5,"Xp6JUx":2,"react-is":11}],7:[function(require,module,exports){
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var ReactPropTypesSecret = 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED';
module.exports = ReactPropTypesSecret;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJSZWFjdFByb3BUeXBlc1NlY3JldCIsIm1vZHVsZSIsImV4cG9ydHMiXSwic291cmNlcyI6WyJSZWFjdFByb3BUeXBlc1NlY3JldC5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIENvcHlyaWdodCAoYykgMjAxMy1wcmVzZW50LCBGYWNlYm9vaywgSW5jLlxuICpcbiAqIFRoaXMgc291cmNlIGNvZGUgaXMgbGljZW5zZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlIGZvdW5kIGluIHRoZVxuICogTElDRU5TRSBmaWxlIGluIHRoZSByb290IGRpcmVjdG9yeSBvZiB0aGlzIHNvdXJjZSB0cmVlLlxuICovXG5cbid1c2Ugc3RyaWN0JztcblxudmFyIFJlYWN0UHJvcFR5cGVzU2VjcmV0ID0gJ1NFQ1JFVF9ET19OT1RfUEFTU19USElTX09SX1lPVV9XSUxMX0JFX0ZJUkVEJztcblxubW9kdWxlLmV4cG9ydHMgPSBSZWFjdFByb3BUeXBlc1NlY3JldDtcbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLFlBQVk7O0FBRVosSUFBSUEsb0JBQW9CLEdBQUcsOENBQThDO0FBRXpFQyxNQUFNLENBQUNDLE9BQU8sR0FBR0Ysb0JBQW9CIn0=
},{}],8:[function(require,module,exports){
module.exports = Function.call.bind(Object.prototype.hasOwnProperty);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJtb2R1bGUiLCJleHBvcnRzIiwiRnVuY3Rpb24iLCJjYWxsIiwiYmluZCIsIk9iamVjdCIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5Il0sInNvdXJjZXMiOlsiaGFzLmpzIl0sInNvdXJjZXNDb250ZW50IjpbIm1vZHVsZS5leHBvcnRzID0gRnVuY3Rpb24uY2FsbC5iaW5kKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkpO1xuIl0sIm1hcHBpbmdzIjoiQUFBQUEsTUFBTSxDQUFDQyxPQUFPLEdBQUdDLFFBQVEsQ0FBQ0MsSUFBSSxDQUFDQyxJQUFJLENBQUNDLE1BQU0sQ0FBQ0MsU0FBUyxDQUFDQyxjQUFjLENBQUMifQ==
},{}],9:[function(require,module,exports){
(function (process){
/** @license React v16.13.1
 * react-is.development.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

if (process.env.NODE_ENV !== "production") {
  (function () {
    'use strict';

    // The Symbol used to tag the ReactElement-like types. If there is no native Symbol
    // nor polyfill, then a plain number is used for performance.
    var hasSymbol = typeof Symbol === 'function' && Symbol.for;
    var REACT_ELEMENT_TYPE = hasSymbol ? Symbol.for('react.element') : 0xeac7;
    var REACT_PORTAL_TYPE = hasSymbol ? Symbol.for('react.portal') : 0xeaca;
    var REACT_FRAGMENT_TYPE = hasSymbol ? Symbol.for('react.fragment') : 0xeacb;
    var REACT_STRICT_MODE_TYPE = hasSymbol ? Symbol.for('react.strict_mode') : 0xeacc;
    var REACT_PROFILER_TYPE = hasSymbol ? Symbol.for('react.profiler') : 0xead2;
    var REACT_PROVIDER_TYPE = hasSymbol ? Symbol.for('react.provider') : 0xeacd;
    var REACT_CONTEXT_TYPE = hasSymbol ? Symbol.for('react.context') : 0xeace; // TODO: We don't use AsyncMode or ConcurrentMode anymore. They were temporary
    // (unstable) APIs that have been removed. Can we remove the symbols?

    var REACT_ASYNC_MODE_TYPE = hasSymbol ? Symbol.for('react.async_mode') : 0xeacf;
    var REACT_CONCURRENT_MODE_TYPE = hasSymbol ? Symbol.for('react.concurrent_mode') : 0xeacf;
    var REACT_FORWARD_REF_TYPE = hasSymbol ? Symbol.for('react.forward_ref') : 0xead0;
    var REACT_SUSPENSE_TYPE = hasSymbol ? Symbol.for('react.suspense') : 0xead1;
    var REACT_SUSPENSE_LIST_TYPE = hasSymbol ? Symbol.for('react.suspense_list') : 0xead8;
    var REACT_MEMO_TYPE = hasSymbol ? Symbol.for('react.memo') : 0xead3;
    var REACT_LAZY_TYPE = hasSymbol ? Symbol.for('react.lazy') : 0xead4;
    var REACT_BLOCK_TYPE = hasSymbol ? Symbol.for('react.block') : 0xead9;
    var REACT_FUNDAMENTAL_TYPE = hasSymbol ? Symbol.for('react.fundamental') : 0xead5;
    var REACT_RESPONDER_TYPE = hasSymbol ? Symbol.for('react.responder') : 0xead6;
    var REACT_SCOPE_TYPE = hasSymbol ? Symbol.for('react.scope') : 0xead7;
    function isValidElementType(type) {
      return typeof type === 'string' || typeof type === 'function' ||
      // Note: its typeof might be other than 'symbol' or 'number' if it's a polyfill.
      type === REACT_FRAGMENT_TYPE || type === REACT_CONCURRENT_MODE_TYPE || type === REACT_PROFILER_TYPE || type === REACT_STRICT_MODE_TYPE || type === REACT_SUSPENSE_TYPE || type === REACT_SUSPENSE_LIST_TYPE || typeof type === 'object' && type !== null && (type.$$typeof === REACT_LAZY_TYPE || type.$$typeof === REACT_MEMO_TYPE || type.$$typeof === REACT_PROVIDER_TYPE || type.$$typeof === REACT_CONTEXT_TYPE || type.$$typeof === REACT_FORWARD_REF_TYPE || type.$$typeof === REACT_FUNDAMENTAL_TYPE || type.$$typeof === REACT_RESPONDER_TYPE || type.$$typeof === REACT_SCOPE_TYPE || type.$$typeof === REACT_BLOCK_TYPE);
    }
    function typeOf(object) {
      if (typeof object === 'object' && object !== null) {
        var $$typeof = object.$$typeof;
        switch ($$typeof) {
          case REACT_ELEMENT_TYPE:
            var type = object.type;
            switch (type) {
              case REACT_ASYNC_MODE_TYPE:
              case REACT_CONCURRENT_MODE_TYPE:
              case REACT_FRAGMENT_TYPE:
              case REACT_PROFILER_TYPE:
              case REACT_STRICT_MODE_TYPE:
              case REACT_SUSPENSE_TYPE:
                return type;
              default:
                var $$typeofType = type && type.$$typeof;
                switch ($$typeofType) {
                  case REACT_CONTEXT_TYPE:
                  case REACT_FORWARD_REF_TYPE:
                  case REACT_LAZY_TYPE:
                  case REACT_MEMO_TYPE:
                  case REACT_PROVIDER_TYPE:
                    return $$typeofType;
                  default:
                    return $$typeof;
                }
            }
          case REACT_PORTAL_TYPE:
            return $$typeof;
        }
      }
      return undefined;
    } // AsyncMode is deprecated along with isAsyncMode

    var AsyncMode = REACT_ASYNC_MODE_TYPE;
    var ConcurrentMode = REACT_CONCURRENT_MODE_TYPE;
    var ContextConsumer = REACT_CONTEXT_TYPE;
    var ContextProvider = REACT_PROVIDER_TYPE;
    var Element = REACT_ELEMENT_TYPE;
    var ForwardRef = REACT_FORWARD_REF_TYPE;
    var Fragment = REACT_FRAGMENT_TYPE;
    var Lazy = REACT_LAZY_TYPE;
    var Memo = REACT_MEMO_TYPE;
    var Portal = REACT_PORTAL_TYPE;
    var Profiler = REACT_PROFILER_TYPE;
    var StrictMode = REACT_STRICT_MODE_TYPE;
    var Suspense = REACT_SUSPENSE_TYPE;
    var hasWarnedAboutDeprecatedIsAsyncMode = false; // AsyncMode should be deprecated

    function isAsyncMode(object) {
      {
        if (!hasWarnedAboutDeprecatedIsAsyncMode) {
          hasWarnedAboutDeprecatedIsAsyncMode = true; // Using console['warn'] to evade Babel and ESLint

          console['warn']('The ReactIs.isAsyncMode() alias has been deprecated, ' + 'and will be removed in React 17+. Update your code to use ' + 'ReactIs.isConcurrentMode() instead. It has the exact same API.');
        }
      }
      return isConcurrentMode(object) || typeOf(object) === REACT_ASYNC_MODE_TYPE;
    }
    function isConcurrentMode(object) {
      return typeOf(object) === REACT_CONCURRENT_MODE_TYPE;
    }
    function isContextConsumer(object) {
      return typeOf(object) === REACT_CONTEXT_TYPE;
    }
    function isContextProvider(object) {
      return typeOf(object) === REACT_PROVIDER_TYPE;
    }
    function isElement(object) {
      return typeof object === 'object' && object !== null && object.$$typeof === REACT_ELEMENT_TYPE;
    }
    function isForwardRef(object) {
      return typeOf(object) === REACT_FORWARD_REF_TYPE;
    }
    function isFragment(object) {
      return typeOf(object) === REACT_FRAGMENT_TYPE;
    }
    function isLazy(object) {
      return typeOf(object) === REACT_LAZY_TYPE;
    }
    function isMemo(object) {
      return typeOf(object) === REACT_MEMO_TYPE;
    }
    function isPortal(object) {
      return typeOf(object) === REACT_PORTAL_TYPE;
    }
    function isProfiler(object) {
      return typeOf(object) === REACT_PROFILER_TYPE;
    }
    function isStrictMode(object) {
      return typeOf(object) === REACT_STRICT_MODE_TYPE;
    }
    function isSuspense(object) {
      return typeOf(object) === REACT_SUSPENSE_TYPE;
    }
    exports.AsyncMode = AsyncMode;
    exports.ConcurrentMode = ConcurrentMode;
    exports.ContextConsumer = ContextConsumer;
    exports.ContextProvider = ContextProvider;
    exports.Element = Element;
    exports.ForwardRef = ForwardRef;
    exports.Fragment = Fragment;
    exports.Lazy = Lazy;
    exports.Memo = Memo;
    exports.Portal = Portal;
    exports.Profiler = Profiler;
    exports.StrictMode = StrictMode;
    exports.Suspense = Suspense;
    exports.isAsyncMode = isAsyncMode;
    exports.isConcurrentMode = isConcurrentMode;
    exports.isContextConsumer = isContextConsumer;
    exports.isContextProvider = isContextProvider;
    exports.isElement = isElement;
    exports.isForwardRef = isForwardRef;
    exports.isFragment = isFragment;
    exports.isLazy = isLazy;
    exports.isMemo = isMemo;
    exports.isPortal = isPortal;
    exports.isProfiler = isProfiler;
    exports.isStrictMode = isStrictMode;
    exports.isSuspense = isSuspense;
    exports.isValidElementType = isValidElementType;
    exports.typeOf = typeOf;
  })();
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJoYXNTeW1ib2wiLCJTeW1ib2wiLCJmb3IiLCJSRUFDVF9FTEVNRU5UX1RZUEUiLCJSRUFDVF9QT1JUQUxfVFlQRSIsIlJFQUNUX0ZSQUdNRU5UX1RZUEUiLCJSRUFDVF9TVFJJQ1RfTU9ERV9UWVBFIiwiUkVBQ1RfUFJPRklMRVJfVFlQRSIsIlJFQUNUX1BST1ZJREVSX1RZUEUiLCJSRUFDVF9DT05URVhUX1RZUEUiLCJSRUFDVF9BU1lOQ19NT0RFX1RZUEUiLCJSRUFDVF9DT05DVVJSRU5UX01PREVfVFlQRSIsIlJFQUNUX0ZPUldBUkRfUkVGX1RZUEUiLCJSRUFDVF9TVVNQRU5TRV9UWVBFIiwiUkVBQ1RfU1VTUEVOU0VfTElTVF9UWVBFIiwiUkVBQ1RfTUVNT19UWVBFIiwiUkVBQ1RfTEFaWV9UWVBFIiwiUkVBQ1RfQkxPQ0tfVFlQRSIsIlJFQUNUX0ZVTkRBTUVOVEFMX1RZUEUiLCJSRUFDVF9SRVNQT05ERVJfVFlQRSIsIlJFQUNUX1NDT1BFX1RZUEUiLCJpc1ZhbGlkRWxlbWVudFR5cGUiLCJ0eXBlIiwiJCR0eXBlb2YiLCJ0eXBlT2YiLCJvYmplY3QiLCIkJHR5cGVvZlR5cGUiLCJ1bmRlZmluZWQiLCJBc3luY01vZGUiLCJDb25jdXJyZW50TW9kZSIsIkNvbnRleHRDb25zdW1lciIsIkNvbnRleHRQcm92aWRlciIsIkVsZW1lbnQiLCJGb3J3YXJkUmVmIiwiRnJhZ21lbnQiLCJMYXp5IiwiTWVtbyIsIlBvcnRhbCIsIlByb2ZpbGVyIiwiU3RyaWN0TW9kZSIsIlN1c3BlbnNlIiwiaGFzV2FybmVkQWJvdXREZXByZWNhdGVkSXNBc3luY01vZGUiLCJpc0FzeW5jTW9kZSIsImNvbnNvbGUiLCJpc0NvbmN1cnJlbnRNb2RlIiwiaXNDb250ZXh0Q29uc3VtZXIiLCJpc0NvbnRleHRQcm92aWRlciIsImlzRWxlbWVudCIsImlzRm9yd2FyZFJlZiIsImlzRnJhZ21lbnQiLCJpc0xhenkiLCJpc01lbW8iLCJpc1BvcnRhbCIsImlzUHJvZmlsZXIiLCJpc1N0cmljdE1vZGUiLCJpc1N1c3BlbnNlIiwiZXhwb3J0cyJdLCJzb3VyY2VzIjpbInJlYWN0LWlzLmRldmVsb3BtZW50LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qKiBAbGljZW5zZSBSZWFjdCB2MTYuMTMuMVxuICogcmVhY3QtaXMuZGV2ZWxvcG1lbnQuanNcbiAqXG4gKiBDb3B5cmlnaHQgKGMpIEZhY2Vib29rLCBJbmMuIGFuZCBpdHMgYWZmaWxpYXRlcy5cbiAqXG4gKiBUaGlzIHNvdXJjZSBjb2RlIGlzIGxpY2Vuc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZSBmb3VuZCBpbiB0aGVcbiAqIExJQ0VOU0UgZmlsZSBpbiB0aGUgcm9vdCBkaXJlY3Rvcnkgb2YgdGhpcyBzb3VyY2UgdHJlZS5cbiAqL1xuXG4ndXNlIHN0cmljdCc7XG5cblxuXG5pZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09IFwicHJvZHVjdGlvblwiKSB7XG4gIChmdW5jdGlvbigpIHtcbid1c2Ugc3RyaWN0JztcblxuLy8gVGhlIFN5bWJvbCB1c2VkIHRvIHRhZyB0aGUgUmVhY3RFbGVtZW50LWxpa2UgdHlwZXMuIElmIHRoZXJlIGlzIG5vIG5hdGl2ZSBTeW1ib2xcbi8vIG5vciBwb2x5ZmlsbCwgdGhlbiBhIHBsYWluIG51bWJlciBpcyB1c2VkIGZvciBwZXJmb3JtYW5jZS5cbnZhciBoYXNTeW1ib2wgPSB0eXBlb2YgU3ltYm9sID09PSAnZnVuY3Rpb24nICYmIFN5bWJvbC5mb3I7XG52YXIgUkVBQ1RfRUxFTUVOVF9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3QuZWxlbWVudCcpIDogMHhlYWM3O1xudmFyIFJFQUNUX1BPUlRBTF9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3QucG9ydGFsJykgOiAweGVhY2E7XG52YXIgUkVBQ1RfRlJBR01FTlRfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LmZyYWdtZW50JykgOiAweGVhY2I7XG52YXIgUkVBQ1RfU1RSSUNUX01PREVfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LnN0cmljdF9tb2RlJykgOiAweGVhY2M7XG52YXIgUkVBQ1RfUFJPRklMRVJfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LnByb2ZpbGVyJykgOiAweGVhZDI7XG52YXIgUkVBQ1RfUFJPVklERVJfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LnByb3ZpZGVyJykgOiAweGVhY2Q7XG52YXIgUkVBQ1RfQ09OVEVYVF9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3QuY29udGV4dCcpIDogMHhlYWNlOyAvLyBUT0RPOiBXZSBkb24ndCB1c2UgQXN5bmNNb2RlIG9yIENvbmN1cnJlbnRNb2RlIGFueW1vcmUuIFRoZXkgd2VyZSB0ZW1wb3Jhcnlcbi8vICh1bnN0YWJsZSkgQVBJcyB0aGF0IGhhdmUgYmVlbiByZW1vdmVkLiBDYW4gd2UgcmVtb3ZlIHRoZSBzeW1ib2xzP1xuXG52YXIgUkVBQ1RfQVNZTkNfTU9ERV9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3QuYXN5bmNfbW9kZScpIDogMHhlYWNmO1xudmFyIFJFQUNUX0NPTkNVUlJFTlRfTU9ERV9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3QuY29uY3VycmVudF9tb2RlJykgOiAweGVhY2Y7XG52YXIgUkVBQ1RfRk9SV0FSRF9SRUZfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LmZvcndhcmRfcmVmJykgOiAweGVhZDA7XG52YXIgUkVBQ1RfU1VTUEVOU0VfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LnN1c3BlbnNlJykgOiAweGVhZDE7XG52YXIgUkVBQ1RfU1VTUEVOU0VfTElTVF9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3Quc3VzcGVuc2VfbGlzdCcpIDogMHhlYWQ4O1xudmFyIFJFQUNUX01FTU9fVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0Lm1lbW8nKSA6IDB4ZWFkMztcbnZhciBSRUFDVF9MQVpZX1RZUEUgPSBoYXNTeW1ib2wgPyBTeW1ib2wuZm9yKCdyZWFjdC5sYXp5JykgOiAweGVhZDQ7XG52YXIgUkVBQ1RfQkxPQ0tfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LmJsb2NrJykgOiAweGVhZDk7XG52YXIgUkVBQ1RfRlVOREFNRU5UQUxfVFlQRSA9IGhhc1N5bWJvbCA/IFN5bWJvbC5mb3IoJ3JlYWN0LmZ1bmRhbWVudGFsJykgOiAweGVhZDU7XG52YXIgUkVBQ1RfUkVTUE9OREVSX1RZUEUgPSBoYXNTeW1ib2wgPyBTeW1ib2wuZm9yKCdyZWFjdC5yZXNwb25kZXInKSA6IDB4ZWFkNjtcbnZhciBSRUFDVF9TQ09QRV9UWVBFID0gaGFzU3ltYm9sID8gU3ltYm9sLmZvcigncmVhY3Quc2NvcGUnKSA6IDB4ZWFkNztcblxuZnVuY3Rpb24gaXNWYWxpZEVsZW1lbnRUeXBlKHR5cGUpIHtcbiAgcmV0dXJuIHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJyB8fCB0eXBlb2YgdHlwZSA9PT0gJ2Z1bmN0aW9uJyB8fCAvLyBOb3RlOiBpdHMgdHlwZW9mIG1pZ2h0IGJlIG90aGVyIHRoYW4gJ3N5bWJvbCcgb3IgJ251bWJlcicgaWYgaXQncyBhIHBvbHlmaWxsLlxuICB0eXBlID09PSBSRUFDVF9GUkFHTUVOVF9UWVBFIHx8IHR5cGUgPT09IFJFQUNUX0NPTkNVUlJFTlRfTU9ERV9UWVBFIHx8IHR5cGUgPT09IFJFQUNUX1BST0ZJTEVSX1RZUEUgfHwgdHlwZSA9PT0gUkVBQ1RfU1RSSUNUX01PREVfVFlQRSB8fCB0eXBlID09PSBSRUFDVF9TVVNQRU5TRV9UWVBFIHx8IHR5cGUgPT09IFJFQUNUX1NVU1BFTlNFX0xJU1RfVFlQRSB8fCB0eXBlb2YgdHlwZSA9PT0gJ29iamVjdCcgJiYgdHlwZSAhPT0gbnVsbCAmJiAodHlwZS4kJHR5cGVvZiA9PT0gUkVBQ1RfTEFaWV9UWVBFIHx8IHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX01FTU9fVFlQRSB8fCB0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9QUk9WSURFUl9UWVBFIHx8IHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX0NPTlRFWFRfVFlQRSB8fCB0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFIHx8IHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX0ZVTkRBTUVOVEFMX1RZUEUgfHwgdHlwZS4kJHR5cGVvZiA9PT0gUkVBQ1RfUkVTUE9OREVSX1RZUEUgfHwgdHlwZS4kJHR5cGVvZiA9PT0gUkVBQ1RfU0NPUEVfVFlQRSB8fCB0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9CTE9DS19UWVBFKTtcbn1cblxuZnVuY3Rpb24gdHlwZU9mKG9iamVjdCkge1xuICBpZiAodHlwZW9mIG9iamVjdCA9PT0gJ29iamVjdCcgJiYgb2JqZWN0ICE9PSBudWxsKSB7XG4gICAgdmFyICQkdHlwZW9mID0gb2JqZWN0LiQkdHlwZW9mO1xuXG4gICAgc3dpdGNoICgkJHR5cGVvZikge1xuICAgICAgY2FzZSBSRUFDVF9FTEVNRU5UX1RZUEU6XG4gICAgICAgIHZhciB0eXBlID0gb2JqZWN0LnR5cGU7XG5cbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgY2FzZSBSRUFDVF9BU1lOQ19NT0RFX1RZUEU6XG4gICAgICAgICAgY2FzZSBSRUFDVF9DT05DVVJSRU5UX01PREVfVFlQRTpcbiAgICAgICAgICBjYXNlIFJFQUNUX0ZSQUdNRU5UX1RZUEU6XG4gICAgICAgICAgY2FzZSBSRUFDVF9QUk9GSUxFUl9UWVBFOlxuICAgICAgICAgIGNhc2UgUkVBQ1RfU1RSSUNUX01PREVfVFlQRTpcbiAgICAgICAgICBjYXNlIFJFQUNUX1NVU1BFTlNFX1RZUEU6XG4gICAgICAgICAgICByZXR1cm4gdHlwZTtcblxuICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB2YXIgJCR0eXBlb2ZUeXBlID0gdHlwZSAmJiB0eXBlLiQkdHlwZW9mO1xuXG4gICAgICAgICAgICBzd2l0Y2ggKCQkdHlwZW9mVHlwZSkge1xuICAgICAgICAgICAgICBjYXNlIFJFQUNUX0NPTlRFWFRfVFlQRTpcbiAgICAgICAgICAgICAgY2FzZSBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFOlxuICAgICAgICAgICAgICBjYXNlIFJFQUNUX0xBWllfVFlQRTpcbiAgICAgICAgICAgICAgY2FzZSBSRUFDVF9NRU1PX1RZUEU6XG4gICAgICAgICAgICAgIGNhc2UgUkVBQ1RfUFJPVklERVJfVFlQRTpcbiAgICAgICAgICAgICAgICByZXR1cm4gJCR0eXBlb2ZUeXBlO1xuXG4gICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuICQkdHlwZW9mO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cblxuICAgICAgY2FzZSBSRUFDVF9QT1JUQUxfVFlQRTpcbiAgICAgICAgcmV0dXJuICQkdHlwZW9mO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiB1bmRlZmluZWQ7XG59IC8vIEFzeW5jTW9kZSBpcyBkZXByZWNhdGVkIGFsb25nIHdpdGggaXNBc3luY01vZGVcblxudmFyIEFzeW5jTW9kZSA9IFJFQUNUX0FTWU5DX01PREVfVFlQRTtcbnZhciBDb25jdXJyZW50TW9kZSA9IFJFQUNUX0NPTkNVUlJFTlRfTU9ERV9UWVBFO1xudmFyIENvbnRleHRDb25zdW1lciA9IFJFQUNUX0NPTlRFWFRfVFlQRTtcbnZhciBDb250ZXh0UHJvdmlkZXIgPSBSRUFDVF9QUk9WSURFUl9UWVBFO1xudmFyIEVsZW1lbnQgPSBSRUFDVF9FTEVNRU5UX1RZUEU7XG52YXIgRm9yd2FyZFJlZiA9IFJFQUNUX0ZPUldBUkRfUkVGX1RZUEU7XG52YXIgRnJhZ21lbnQgPSBSRUFDVF9GUkFHTUVOVF9UWVBFO1xudmFyIExhenkgPSBSRUFDVF9MQVpZX1RZUEU7XG52YXIgTWVtbyA9IFJFQUNUX01FTU9fVFlQRTtcbnZhciBQb3J0YWwgPSBSRUFDVF9QT1JUQUxfVFlQRTtcbnZhciBQcm9maWxlciA9IFJFQUNUX1BST0ZJTEVSX1RZUEU7XG52YXIgU3RyaWN0TW9kZSA9IFJFQUNUX1NUUklDVF9NT0RFX1RZUEU7XG52YXIgU3VzcGVuc2UgPSBSRUFDVF9TVVNQRU5TRV9UWVBFO1xudmFyIGhhc1dhcm5lZEFib3V0RGVwcmVjYXRlZElzQXN5bmNNb2RlID0gZmFsc2U7IC8vIEFzeW5jTW9kZSBzaG91bGQgYmUgZGVwcmVjYXRlZFxuXG5mdW5jdGlvbiBpc0FzeW5jTW9kZShvYmplY3QpIHtcbiAge1xuICAgIGlmICghaGFzV2FybmVkQWJvdXREZXByZWNhdGVkSXNBc3luY01vZGUpIHtcbiAgICAgIGhhc1dhcm5lZEFib3V0RGVwcmVjYXRlZElzQXN5bmNNb2RlID0gdHJ1ZTsgLy8gVXNpbmcgY29uc29sZVsnd2FybiddIHRvIGV2YWRlIEJhYmVsIGFuZCBFU0xpbnRcblxuICAgICAgY29uc29sZVsnd2FybiddKCdUaGUgUmVhY3RJcy5pc0FzeW5jTW9kZSgpIGFsaWFzIGhhcyBiZWVuIGRlcHJlY2F0ZWQsICcgKyAnYW5kIHdpbGwgYmUgcmVtb3ZlZCBpbiBSZWFjdCAxNysuIFVwZGF0ZSB5b3VyIGNvZGUgdG8gdXNlICcgKyAnUmVhY3RJcy5pc0NvbmN1cnJlbnRNb2RlKCkgaW5zdGVhZC4gSXQgaGFzIHRoZSBleGFjdCBzYW1lIEFQSS4nKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gaXNDb25jdXJyZW50TW9kZShvYmplY3QpIHx8IHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9BU1lOQ19NT0RFX1RZUEU7XG59XG5mdW5jdGlvbiBpc0NvbmN1cnJlbnRNb2RlKG9iamVjdCkge1xuICByZXR1cm4gdHlwZU9mKG9iamVjdCkgPT09IFJFQUNUX0NPTkNVUlJFTlRfTU9ERV9UWVBFO1xufVxuZnVuY3Rpb24gaXNDb250ZXh0Q29uc3VtZXIob2JqZWN0KSB7XG4gIHJldHVybiB0eXBlT2Yob2JqZWN0KSA9PT0gUkVBQ1RfQ09OVEVYVF9UWVBFO1xufVxuZnVuY3Rpb24gaXNDb250ZXh0UHJvdmlkZXIob2JqZWN0KSB7XG4gIHJldHVybiB0eXBlT2Yob2JqZWN0KSA9PT0gUkVBQ1RfUFJPVklERVJfVFlQRTtcbn1cbmZ1bmN0aW9uIGlzRWxlbWVudChvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVvZiBvYmplY3QgPT09ICdvYmplY3QnICYmIG9iamVjdCAhPT0gbnVsbCAmJiBvYmplY3QuJCR0eXBlb2YgPT09IFJFQUNUX0VMRU1FTlRfVFlQRTtcbn1cbmZ1bmN0aW9uIGlzRm9yd2FyZFJlZihvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFO1xufVxuZnVuY3Rpb24gaXNGcmFnbWVudChvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9GUkFHTUVOVF9UWVBFO1xufVxuZnVuY3Rpb24gaXNMYXp5KG9iamVjdCkge1xuICByZXR1cm4gdHlwZU9mKG9iamVjdCkgPT09IFJFQUNUX0xBWllfVFlQRTtcbn1cbmZ1bmN0aW9uIGlzTWVtbyhvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9NRU1PX1RZUEU7XG59XG5mdW5jdGlvbiBpc1BvcnRhbChvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9QT1JUQUxfVFlQRTtcbn1cbmZ1bmN0aW9uIGlzUHJvZmlsZXIob2JqZWN0KSB7XG4gIHJldHVybiB0eXBlT2Yob2JqZWN0KSA9PT0gUkVBQ1RfUFJPRklMRVJfVFlQRTtcbn1cbmZ1bmN0aW9uIGlzU3RyaWN0TW9kZShvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9TVFJJQ1RfTU9ERV9UWVBFO1xufVxuZnVuY3Rpb24gaXNTdXNwZW5zZShvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVPZihvYmplY3QpID09PSBSRUFDVF9TVVNQRU5TRV9UWVBFO1xufVxuXG5leHBvcnRzLkFzeW5jTW9kZSA9IEFzeW5jTW9kZTtcbmV4cG9ydHMuQ29uY3VycmVudE1vZGUgPSBDb25jdXJyZW50TW9kZTtcbmV4cG9ydHMuQ29udGV4dENvbnN1bWVyID0gQ29udGV4dENvbnN1bWVyO1xuZXhwb3J0cy5Db250ZXh0UHJvdmlkZXIgPSBDb250ZXh0UHJvdmlkZXI7XG5leHBvcnRzLkVsZW1lbnQgPSBFbGVtZW50O1xuZXhwb3J0cy5Gb3J3YXJkUmVmID0gRm9yd2FyZFJlZjtcbmV4cG9ydHMuRnJhZ21lbnQgPSBGcmFnbWVudDtcbmV4cG9ydHMuTGF6eSA9IExhenk7XG5leHBvcnRzLk1lbW8gPSBNZW1vO1xuZXhwb3J0cy5Qb3J0YWwgPSBQb3J0YWw7XG5leHBvcnRzLlByb2ZpbGVyID0gUHJvZmlsZXI7XG5leHBvcnRzLlN0cmljdE1vZGUgPSBTdHJpY3RNb2RlO1xuZXhwb3J0cy5TdXNwZW5zZSA9IFN1c3BlbnNlO1xuZXhwb3J0cy5pc0FzeW5jTW9kZSA9IGlzQXN5bmNNb2RlO1xuZXhwb3J0cy5pc0NvbmN1cnJlbnRNb2RlID0gaXNDb25jdXJyZW50TW9kZTtcbmV4cG9ydHMuaXNDb250ZXh0Q29uc3VtZXIgPSBpc0NvbnRleHRDb25zdW1lcjtcbmV4cG9ydHMuaXNDb250ZXh0UHJvdmlkZXIgPSBpc0NvbnRleHRQcm92aWRlcjtcbmV4cG9ydHMuaXNFbGVtZW50ID0gaXNFbGVtZW50O1xuZXhwb3J0cy5pc0ZvcndhcmRSZWYgPSBpc0ZvcndhcmRSZWY7XG5leHBvcnRzLmlzRnJhZ21lbnQgPSBpc0ZyYWdtZW50O1xuZXhwb3J0cy5pc0xhenkgPSBpc0xhenk7XG5leHBvcnRzLmlzTWVtbyA9IGlzTWVtbztcbmV4cG9ydHMuaXNQb3J0YWwgPSBpc1BvcnRhbDtcbmV4cG9ydHMuaXNQcm9maWxlciA9IGlzUHJvZmlsZXI7XG5leHBvcnRzLmlzU3RyaWN0TW9kZSA9IGlzU3RyaWN0TW9kZTtcbmV4cG9ydHMuaXNTdXNwZW5zZSA9IGlzU3VzcGVuc2U7XG5leHBvcnRzLmlzVmFsaWRFbGVtZW50VHlwZSA9IGlzVmFsaWRFbGVtZW50VHlwZTtcbmV4cG9ydHMudHlwZU9mID0gdHlwZU9mO1xuICB9KSgpO1xufVxuIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLFlBQVk7O0FBSVosSUFBSUEsT0FBTyxDQUFDQyxHQUFHLENBQUNDLFFBQVEsS0FBSyxZQUFZLEVBQUU7RUFDekMsQ0FBQyxZQUFXO0lBQ2QsWUFBWTs7SUFFWjtJQUNBO0lBQ0EsSUFBSUMsU0FBUyxHQUFHLE9BQU9DLE1BQU0sS0FBSyxVQUFVLElBQUlBLE1BQU0sQ0FBQ0MsR0FBRztJQUMxRCxJQUFJQyxrQkFBa0IsR0FBR0gsU0FBUyxHQUFHQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxlQUFlLENBQUMsR0FBRyxNQUFNO0lBQ3pFLElBQUlFLGlCQUFpQixHQUFHSixTQUFTLEdBQUdDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGNBQWMsQ0FBQyxHQUFHLE1BQU07SUFDdkUsSUFBSUcsbUJBQW1CLEdBQUdMLFNBQVMsR0FBR0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsZ0JBQWdCLENBQUMsR0FBRyxNQUFNO0lBQzNFLElBQUlJLHNCQUFzQixHQUFHTixTQUFTLEdBQUdDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLG1CQUFtQixDQUFDLEdBQUcsTUFBTTtJQUNqRixJQUFJSyxtQkFBbUIsR0FBR1AsU0FBUyxHQUFHQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxnQkFBZ0IsQ0FBQyxHQUFHLE1BQU07SUFDM0UsSUFBSU0sbUJBQW1CLEdBQUdSLFNBQVMsR0FBR0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsZ0JBQWdCLENBQUMsR0FBRyxNQUFNO0lBQzNFLElBQUlPLGtCQUFrQixHQUFHVCxTQUFTLEdBQUdDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGVBQWUsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxDQUFDO0lBQzNFOztJQUVBLElBQUlRLHFCQUFxQixHQUFHVixTQUFTLEdBQUdD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
}).call(this,require("Xp6JUx"))
},{"Xp6JUx":2}],10:[function(require,module,exports){
/** @license React v16.13.1
 * react-is.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var b = "function" === typeof Symbol && Symbol.for,
  c = b ? Symbol.for("react.element") : 60103,
  d = b ? Symbol.for("react.portal") : 60106,
  e = b ? Symbol.for("react.fragment") : 60107,
  f = b ? Symbol.for("react.strict_mode") : 60108,
  g = b ? Symbol.for("react.profiler") : 60114,
  h = b ? Symbol.for("react.provider") : 60109,
  k = b ? Symbol.for("react.context") : 60110,
  l = b ? Symbol.for("react.async_mode") : 60111,
  m = b ? Symbol.for("react.concurrent_mode") : 60111,
  n = b ? Symbol.for("react.forward_ref") : 60112,
  p = b ? Symbol.for("react.suspense") : 60113,
  q = b ? Symbol.for("react.suspense_list") : 60120,
  r = b ? Symbol.for("react.memo") : 60115,
  t = b ? Symbol.for("react.lazy") : 60116,
  v = b ? Symbol.for("react.block") : 60121,
  w = b ? Symbol.for("react.fundamental") : 60117,
  x = b ? Symbol.for("react.responder") : 60118,
  y = b ? Symbol.for("react.scope") : 60119;
function z(a) {
  if ("object" === typeof a && null !== a) {
    var u = a.$$typeof;
    switch (u) {
      case c:
        switch (a = a.type, a) {
          case l:
          case m:
          case e:
          case g:
          case f:
          case p:
            return a;
          default:
            switch (a = a && a.$$typeof, a) {
              case k:
              case n:
              case t:
              case r:
              case h:
                return a;
              default:
                return u;
            }
        }
      case d:
        return u;
    }
  }
}
function A(a) {
  return z(a) === m;
}
exports.AsyncMode = l;
exports.ConcurrentMode = m;
exports.ContextConsumer = k;
exports.ContextProvider = h;
exports.Element = c;
exports.ForwardRef = n;
exports.Fragment = e;
exports.Lazy = t;
exports.Memo = r;
exports.Portal = d;
exports.Profiler = g;
exports.StrictMode = f;
exports.Suspense = p;
exports.isAsyncMode = function (a) {
  return A(a) || z(a) === l;
};
exports.isConcurrentMode = A;
exports.isContextConsumer = function (a) {
  return z(a) === k;
};
exports.isContextProvider = function (a) {
  return z(a) === h;
};
exports.isElement = function (a) {
  return "object" === typeof a && null !== a && a.$$typeof === c;
};
exports.isForwardRef = function (a) {
  return z(a) === n;
};
exports.isFragment = function (a) {
  return z(a) === e;
};
exports.isLazy = function (a) {
  return z(a) === t;
};
exports.isMemo = function (a) {
  return z(a) === r;
};
exports.isPortal = function (a) {
  return z(a) === d;
};
exports.isProfiler = function (a) {
  return z(a) === g;
};
exports.isStrictMode = function (a) {
  return z(a) === f;
};
exports.isSuspense = function (a) {
  return z(a) === p;
};
exports.isValidElementType = function (a) {
  return "string" === typeof a || "function" === typeof a || a === e || a === m || a === g || a === f || a === p || a === q || "object" === typeof a && null !== a && (a.$$typeof === t || a.$$typeof === r || a.$$typeof === h || a.$$typeof === k || a.$$typeof === n || a.$$typeof === w || a.$$typeof === x || a.$$typeof === y || a.$$typeof === v);
};
exports.typeOf = z;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJiIiwiU3ltYm9sIiwiZm9yIiwiYyIsImQiLCJlIiwiZiIsImciLCJoIiwiayIsImwiLCJtIiwibiIsInAiLCJxIiwiciIsInQiLCJ2IiwidyIsIngiLCJ5IiwieiIsImEiLCJ1IiwiJCR0eXBlb2YiLCJ0eXBlIiwiQSIsImV4cG9ydHMiLCJBc3luY01vZGUiLCJDb25jdXJyZW50TW9kZSIsIkNvbnRleHRDb25zdW1lciIsIkNvbnRleHRQcm92aWRlciIsIkVsZW1lbnQiLCJGb3J3YXJkUmVmIiwiRnJhZ21lbnQiLCJMYXp5IiwiTWVtbyIsIlBvcnRhbCIsIlByb2ZpbGVyIiwiU3RyaWN0TW9kZSIsIlN1c3BlbnNlIiwiaXNBc3luY01vZGUiLCJpc0NvbmN1cnJlbnRNb2RlIiwiaXNDb250ZXh0Q29uc3VtZXIiLCJpc0NvbnRleHRQcm92aWRlciIsImlzRWxlbWVudCIsImlzRm9yd2FyZFJlZiIsImlzRnJhZ21lbnQiLCJpc0xhenkiLCJpc01lbW8iLCJpc1BvcnRhbCIsImlzUHJvZmlsZXIiLCJpc1N0cmljdE1vZGUiLCJpc1N1c3BlbnNlIiwiaXNWYWxpZEVsZW1lbnRUeXBlIiwidHlwZU9mIl0sInNvdXJjZXMiOlsicmVhY3QtaXMucHJvZHVjdGlvbi5taW4uanMiXSwic291cmNlc0NvbnRlbnQiOlsiLyoqIEBsaWNlbnNlIFJlYWN0IHYxNi4xMy4xXG4gKiByZWFjdC1pcy5wcm9kdWN0aW9uLm1pbi5qc1xuICpcbiAqIENvcHlyaWdodCAoYykgRmFjZWJvb2ssIEluYy4gYW5kIGl0cyBhZmZpbGlhdGVzLlxuICpcbiAqIFRoaXMgc291cmNlIGNvZGUgaXMgbGljZW5zZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlIGZvdW5kIGluIHRoZVxuICogTElDRU5TRSBmaWxlIGluIHRoZSByb290IGRpcmVjdG9yeSBvZiB0aGlzIHNvdXJjZSB0cmVlLlxuICovXG5cbid1c2Ugc3RyaWN0Jzt2YXIgYj1cImZ1bmN0aW9uXCI9PT10eXBlb2YgU3ltYm9sJiZTeW1ib2wuZm9yLGM9Yj9TeW1ib2wuZm9yKFwicmVhY3QuZWxlbWVudFwiKTo2MDEwMyxkPWI/U3ltYm9sLmZvcihcInJlYWN0LnBvcnRhbFwiKTo2MDEwNixlPWI/U3ltYm9sLmZvcihcInJlYWN0LmZyYWdtZW50XCIpOjYwMTA3LGY9Yj9TeW1ib2wuZm9yKFwicmVhY3Quc3RyaWN0X21vZGVcIik6NjAxMDgsZz1iP1N5bWJvbC5mb3IoXCJyZWFjdC5wcm9maWxlclwiKTo2MDExNCxoPWI/U3ltYm9sLmZvcihcInJlYWN0LnByb3ZpZGVyXCIpOjYwMTA5LGs9Yj9TeW1ib2wuZm9yKFwicmVhY3QuY29udGV4dFwiKTo2MDExMCxsPWI/U3ltYm9sLmZvcihcInJlYWN0LmFzeW5jX21vZGVcIik6NjAxMTEsbT1iP1N5bWJvbC5mb3IoXCJyZWFjdC5jb25jdXJyZW50X21vZGVcIik6NjAxMTEsbj1iP1N5bWJvbC5mb3IoXCJyZWFjdC5mb3J3YXJkX3JlZlwiKTo2MDExMixwPWI/U3ltYm9sLmZvcihcInJlYWN0LnN1c3BlbnNlXCIpOjYwMTEzLHE9Yj9cblN5bWJvbC5mb3IoXCJyZWFjdC5zdXNwZW5zZV9saXN0XCIpOjYwMTIwLHI9Yj9TeW1ib2wuZm9yKFwicmVhY3QubWVtb1wiKTo2MDExNSx0PWI/U3ltYm9sLmZvcihcInJlYWN0LmxhenlcIik6NjAxMTYsdj1iP1N5bWJvbC5mb3IoXCJyZWFjdC5ibG9ja1wiKTo2MDEyMSx3PWI/U3ltYm9sLmZvcihcInJlYWN0LmZ1bmRhbWVudGFsXCIpOjYwMTE3LHg9Yj9TeW1ib2wuZm9yKFwicmVhY3QucmVzcG9uZGVyXCIpOjYwMTE4LHk9Yj9TeW1ib2wuZm9yKFwicmVhY3Quc2NvcGVcIik6NjAxMTk7XG5mdW5jdGlvbiB6KGEpe2lmKFwib2JqZWN0XCI9PT10eXBlb2YgYSYmbnVsbCE9PWEpe3ZhciB1PWEuJCR0eXBlb2Y7c3dpdGNoKHUpe2Nhc2UgYzpzd2l0Y2goYT1hLnR5cGUsYSl7Y2FzZSBsOmNhc2UgbTpjYXNlIGU6Y2FzZSBnOmNhc2UgZjpjYXNlIHA6cmV0dXJuIGE7ZGVmYXVsdDpzd2l0Y2goYT1hJiZhLiQkdHlwZW9mLGEpe2Nhc2UgazpjYXNlIG46Y2FzZSB0OmNhc2UgcjpjYXNlIGg6cmV0dXJuIGE7ZGVmYXVsdDpyZXR1cm4gdX19Y2FzZSBkOnJldHVybiB1fX19ZnVuY3Rpb24gQShhKXtyZXR1cm4geihhKT09PW19ZXhwb3J0cy5Bc3luY01vZGU9bDtleHBvcnRzLkNvbmN1cnJlbnRNb2RlPW07ZXhwb3J0cy5Db250ZXh0Q29uc3VtZXI9aztleHBvcnRzLkNvbnRleHRQcm92aWRlcj1oO2V4cG9ydHMuRWxlbWVudD1jO2V4cG9ydHMuRm9yd2FyZFJlZj1uO2V4cG9ydHMuRnJhZ21lbnQ9ZTtleHBvcnRzLkxhenk9dDtleHBvcnRzLk1lbW89cjtleHBvcnRzLlBvcnRhbD1kO1xuZXhwb3J0cy5Qcm9maWxlcj1nO2V4cG9ydHMuU3RyaWN0TW9kZT1mO2V4cG9ydHMuU3VzcGVuc2U9cDtleHBvcnRzLmlzQXN5bmNNb2RlPWZ1bmN0aW9uKGEpe3JldHVybiBBKGEpfHx6KGEpPT09bH07ZXhwb3J0cy5pc0NvbmN1cnJlbnRNb2RlPUE7ZXhwb3J0cy5pc0NvbnRleHRDb25zdW1lcj1mdW5jdGlvbihhKXtyZXR1cm4geihhKT09PWt9O2V4cG9ydHMuaXNDb250ZXh0UHJvdmlkZXI9ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1ofTtleHBvcnRzLmlzRWxlbWVudD1mdW5jdGlvbihhKXtyZXR1cm5cIm9iamVjdFwiPT09dHlwZW9mIGEmJm51bGwhPT1hJiZhLiQkdHlwZW9mPT09Y307ZXhwb3J0cy5pc0ZvcndhcmRSZWY9ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1ufTtleHBvcnRzLmlzRnJhZ21lbnQ9ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1lfTtleHBvcnRzLmlzTGF6eT1mdW5jdGlvbihhKXtyZXR1cm4geihhKT09PXR9O1xuZXhwb3J0cy5pc01lbW89ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1yfTtleHBvcnRzLmlzUG9ydGFsPWZ1bmN0aW9uKGEpe3JldHVybiB6KGEpPT09ZH07ZXhwb3J0cy5pc1Byb2ZpbGVyPWZ1bmN0aW9uKGEpe3JldHVybiB6KGEpPT09Z307ZXhwb3J0cy5pc1N0cmljdE1vZGU9ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1mfTtleHBvcnRzLmlzU3VzcGVuc2U9ZnVuY3Rpb24oYSl7cmV0dXJuIHooYSk9PT1wfTtcbmV4cG9ydHMuaXNWYWxpZEVsZW1lbnRUeXBlPWZ1bmN0aW9uKGEpe3JldHVyblwic3RyaW5nXCI9PT10eXBlb2YgYXx8XCJmdW5jdGlvblwiPT09dHlwZW9mIGF8fGE9PT1lfHxhPT09bXx8YT09PWd8fGE9PT1mfHxhPT09cHx8YT09PXF8fFwib2JqZWN0XCI9PT10eXBlb2YgYSYmbnVsbCE9PWEmJihhLiQkdHlwZW9mPT09dHx8YS4kJHR5cGVvZj09PXJ8fGEuJCR0eXBlb2Y9PT1ofHxhLiQkdHlwZW9mPT09a3x8YS4kJHR5cGVvZj09PW58fGEuJCR0eXBlb2Y9PT13fHxhLiQkdHlwZW9mPT09eHx8YS4kJHR5cGVvZj09PXl8fGEuJCR0eXBlb2Y9PT12KX07ZXhwb3J0cy50eXBlT2Y9ejtcbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxZQUFZOztBQUFDLElBQUlBLENBQUMsR0FBQyxVQUFVLEtBQUcsT0FBT0MsTUFBTSxJQUFFQSxNQUFNLENBQUNDLEdBQUc7RUFBQ0MsQ0FBQyxHQUFDSCxDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGVBQWUsQ0FBQyxHQUFDLEtBQUs7RUFBQ0UsQ0FBQyxHQUFDSixDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGNBQWMsQ0FBQyxHQUFDLEtBQUs7RUFBQ0csQ0FBQyxHQUFDTCxDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGdCQUFnQixDQUFDLEdBQUMsS0FBSztFQUFDSSxDQUFDLEdBQUNOLENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsbUJBQW1CLENBQUMsR0FBQyxLQUFLO0VBQUNLLENBQUMsR0FBQ1AsQ0FBQyxHQUFDQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxnQkFBZ0IsQ0FBQyxHQUFDLEtBQUs7RUFBQ00sQ0FBQyxHQUFDUixDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGdCQUFnQixDQUFDLEdBQUMsS0FBSztFQUFDTyxDQUFDLEdBQUNULENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsZUFBZSxDQUFDLEdBQUMsS0FBSztFQUFDUSxDQUFDLEdBQUNWLENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsa0JBQWtCLENBQUMsR0FBQyxLQUFLO0VBQUNTLENBQUMsR0FBQ1gsQ0FBQyxHQUFDQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyx1QkFBdUIsQ0FBQyxHQUFDLEtBQUs7RUFBQ1UsQ0FBQyxHQUFDWixDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLG1CQUFtQixDQUFDLEdBQUMsS0FBSztFQUFDVyxDQUFDLEdBQUNiLENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsZ0JBQWdCLENBQUMsR0FBQyxLQUFLO0VBQUNZLENBQUMsR0FBQ2QsQ0FBQyxHQUNyZkMsTUFBTSxDQUFDQyxHQUFHLENBQUMscUJBQXFCLENBQUMsR0FBQyxLQUFLO0VBQUNhLENBQUMsR0FBQ2YsQ0FBQyxHQUFDQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxZQUFZLENBQUMsR0FBQyxLQUFLO0VBQUNjLENBQUMsR0FBQ2hCLENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsWUFBWSxDQUFDLEdBQUMsS0FBSztFQUFDZSxDQUFDLEdBQUNqQixDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGFBQWEsQ0FBQyxHQUFDLEtBQUs7RUFBQ2dCLENBQUMsR0FBQ2xCLENBQUMsR0FBQ0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsbUJBQW1CLENBQUMsR0FBQyxLQUFLO0VBQUNpQixDQUFDLEdBQUNuQixDQUFDLEdBQUNDLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGlCQUFpQixDQUFDLEdBQUMsS0FBSztFQUFDa0IsQ0FBQyxHQUFDcEIsQ0FBQyxHQUFDQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxhQUFhLENBQUMsR0FBQyxLQUFLO0FBQ3ZRLFNBQVNtQixDQUFDLENBQUNDLENBQUMsRUFBQztFQUFDLElBQUcsUUFBUSxLQUFHLE9BQU9BLENBQUMsSUFBRSxJQUFJLEtBQUdBLENBQUMsRUFBQztJQUFDLElBQUlDLENBQUMsR0FBQ0QsQ0FBQyxDQUFDRSxRQUFRO0lBQUMsUUFBT0QsQ0FBQztNQUFFLEtBQUtwQixDQUFDO1FBQUMsUUFBT21CLENBQUMsR0FBQ0EsQ0FBQyxDQUFDRyxJQUFJLEVBQUNILENBQUM7VUFBRSxLQUFLWixDQUFDO1VBQUMsS0FBS0MsQ0FBQztVQUFDLEtBQUtOLENBQUM7VUFBQyxLQUFLRSxDQUFDO1VBQUMsS0FBS0QsQ0FBQztVQUFDLEtBQUtPLENBQUM7WUFBQyxPQUFPUyxDQUFDO1VBQUM7WUFBUSxRQUFPQSxDQUFDLEdBQUNBLENBQUMsSUFBRUEsQ0FBQyxDQUFDRSxRQUFRLEVBQUNGLENBQUM7Y0FBRSxLQUFLYixDQUFDO2NBQUMsS0FBS0csQ0FBQztjQUFDLEtBQUtJLENBQUM7Y0FBQyxLQUFLRCxDQUFDO2NBQUMsS0FBS1AsQ0FBQztnQkFBQyxPQUFPYyxDQUFDO2NBQUM7Z0JBQVEsT0FBT0MsQ0FBQztZQUFBO1FBQUM7TUFBQyxLQUFLbkIsQ0FBQztRQUFDLE9BQU9tQixDQUFDO0lBQUE7RUFBQztBQUFDO0FBQUMsU0FBU0csQ0FBQyxDQUFDSixDQUFDLEVBQUM7RUFBQyxPQUFPRCxDQUFDLENBQUNDLENBQUMsQ0FBQyxLQUFHWCxDQUFDO0FBQUE7QUFBQ2dCLE9BQU8sQ0FBQ0MsU0FBUyxHQUFDbEIsQ0FBQztBQUFDaUIsT0FBTyxDQUFDRSxjQUFjLEdBQUNsQixDQUFDO0FBQUNnQixPQUFPLENBQUNHLGVBQWUsR0FBQ3JCLENBQUM7QUFBQ2tCLE9BQU8sQ0FBQ0ksZUFBZSxHQUFDdkIsQ0FBQztBQUFDbUIsT0FBTyxDQUFDSyxPQUFPLEdBQUM3QixDQUFDO0FBQUN3QixPQUFPLENBQUNNLFVBQVUsR0FBQ3JCLENBQUM7QUFBQ2UsT0FBTyxDQUFDTyxRQUFRLEdBQUM3QixDQUFDO0FBQUNzQixPQUFPLENBQUNRLElBQUksR0FBQ25CLENBQUM7QUFBQ1csT0FBTyxDQUFDUyxJQUFJLEdBQUNyQixDQUFDO0FBQUNZLE9BQU8sQ0FBQ1UsTUFBTSxHQUFDakMsQ0FBQztBQUNqZnVCLE9BQU8sQ0FBQ1csUUFBUSxHQUFDL0IsQ0FBQztBQUFDb0IsT0FBTyxDQUFDWSxVQUFVLEdBQUNqQyxDQUFDO0FBQUNxQixPQUFPLENBQUNhLFFBQVEsR0FBQzNCLENBQUM7QUFBQ2MsT0FBTyxDQUFDYyxXQUFXLEdBQUMsVUFBU25CLENBQUMsRUFBQztFQUFDLE9BQU9JLENBQUMsQ0FBQ0osQ0FBQyxDQUFDLElBQUVELENBQUMsQ0FBQ0MsQ0FBQyxDQUFDLEtBQUdaLENBQUM7QUFBQSxDQUFDO0FBQUNpQixPQUFPLENBQUNlLGdCQUFnQixHQUFDaEIsQ0FBQztBQUFDQyxPQUFPLENBQUNnQixpQkFBaUIsR0FBQyxVQUFTckIsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR2IsQ0FBQztBQUFBLENBQUM7QUFBQ2tCLE9BQU8sQ0FBQ2lCLGlCQUFpQixHQUFDLFVBQVN0QixDQUFDLEVBQUM7RUFBQyxPQUFPRCxDQUFDLENBQUNDLENBQUMsQ0FBQyxLQUFHZCxDQUFDO0FBQUEsQ0FBQztBQUFDbUIsT0FBTyxDQUFDa0IsU0FBUyxHQUFDLFVBQVN2QixDQUFDLEVBQUM7RUFBQyxPQUFNLFFBQVEsS0FBRyxPQUFPQSxDQUFDLElBQUUsSUFBSSxLQUFHQSxDQUFDLElBQUVBLENBQUMsQ0FBQ0UsUUFBUSxLQUFHckIsQ0FBQztBQUFBLENBQUM7QUFBQ3dCLE9BQU8sQ0FBQ21CLFlBQVksR0FBQyxVQUFTeEIsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR1YsQ0FBQztBQUFBLENBQUM7QUFBQ2UsT0FBTyxDQUFDb0IsVUFBVSxHQUFDLFVBQVN6QixDQUFDLEVBQUM7RUFBQyxPQUFPRCxDQUFDLENBQUNDLENBQUMsQ0FBQyxLQUFHakIsQ0FBQztBQUFBLENBQUM7QUFBQ3NCLE9BQU8sQ0FBQ3FCLE1BQU0sR0FBQyxVQUFTMUIsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR04sQ0FBQztBQUFBLENBQUM7QUFDM2RXLE9BQU8sQ0FBQ3NCLE1BQU0sR0FBQyxVQUFTM0IsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR1AsQ0FBQztBQUFBLENBQUM7QUFBQ1ksT0FBTyxDQUFDdUIsUUFBUSxHQUFDLFVBQVM1QixDQUFDLEVBQUM7RUFBQyxPQUFPRCxDQUFDLENBQUNDLENBQUMsQ0FBQyxLQUFHbEIsQ0FBQztBQUFBLENBQUM7QUFBQ3VCLE9BQU8sQ0FBQ3dCLFVBQVUsR0FBQyxVQUFTN0IsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR2YsQ0FBQztBQUFBLENBQUM7QUFBQ29CLE9BQU8sQ0FBQ3lCLFlBQVksR0FBQyxVQUFTOUIsQ0FBQyxFQUFDO0VBQUMsT0FBT0QsQ0FBQyxDQUFDQyxDQUFDLENBQUMsS0FBR2hCLENBQUM7QUFBQSxDQUFDO0FBQUNxQixPQUFPLENBQUMwQixVQUFVLEdBQUMsVUFBUy9CLENBQUMsRUFBQztFQUFDLE9BQU9ELENBQUMsQ0FBQ0MsQ0FBQyxDQUFDLEtBQUdULENBQUM7QUFBQSxDQUFDO0FBQzNPYyxPQUFPLENBQUMyQixrQkFBa0IsR0FBQyxVQUFTaEMsQ0FBQyxFQUFDO0VBQUMsT0FBTSxRQUFRLEtBQUcsT0FBT0EsQ0FBQyxJQUFFLFVBQVUsS0FBRyxPQUFPQSxDQUFDLElBQUVBLENBQUMsS0FBR2pCLENBQUMsSUFBRWlCLENBQUMsS0FBR1gsQ0FBQyxJQUFFVyxDQUFDLEtBQUdmLENBQUMsSUFBRWUsQ0FBQyxLQUFHaEIsQ0FBQyxJQUFFZ0IsQ0FBQyxLQUFHVCxDQUFDLElBQUVTLENBQUMsS0FBR1IsQ0FBQyxJQUFFLFFBQVEsS0FBRyxPQUFPUSxDQUFDLElBQUUsSUFBSSxLQUFHQSxDQUFDLEtBQUdBLENBQUMsQ0FBQ0UsUUFBUSxLQUFHUixDQUFDLElBQUVNLENBQUMsQ0FBQ0UsUUFBUSxLQUFHVCxDQUFDLElBQUVPLENBQUMsQ0FBQ0UsUUFBUSxLQUFHaEIsQ0FBQyxJQUFFYyxDQUFDLENBQUNFLFFBQVEsS0FBR2YsQ0FBQyxJQUFFYSxDQUFDLENBQUNFLFFBQVEsS0FBR1osQ0FBQyxJQUFFVSxDQUFDLENBQUNFLFFBQVEsS0FBR04sQ0FBQyxJQUFFSSxDQUFDLENBQUNFLFFBQVEsS0FBR0wsQ0FBQyxJQUFFRyxDQUFDLENBQUNFLFFBQVEsS0FBR0osQ0FBQyxJQUFFRSxDQUFDLENBQUNFLFFBQVEsS0FBR1AsQ0FBQyxDQUFDO0FBQUEsQ0FBQztBQUFDVSxPQUFPLENBQUM0QixNQUFNLEdBQUNsQyxDQUFDIn0=
},{}],11:[function(require,module,exports){
(function (process){
'use strict';

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./cjs/react-is.production.min.js');
} else {
  module.exports = require('./cjs/react-is.development.js');
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJtb2R1bGUiLCJleHBvcnRzIiwicmVxdWlyZSJdLCJzb3VyY2VzIjpbImluZGV4LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcblxuaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicpIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2Nqcy9yZWFjdC1pcy5wcm9kdWN0aW9uLm1pbi5qcycpO1xufSBlbHNlIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2Nqcy9yZWFjdC1pcy5kZXZlbG9wbWVudC5qcycpO1xufVxuIl0sIm1hcHBpbmdzIjoiQUFBQSxZQUFZOztBQUVaLElBQUlBLE9BQU8sQ0FBQ0MsR0FBRyxDQUFDQyxRQUFRLEtBQUssWUFBWSxFQUFFO0VBQ3pDQyxNQUFNLENBQUNDLE9BQU8sR0FBR0MsT0FBTyxDQUFDLGtDQUFrQyxDQUFDO0FBQzlELENBQUMsTUFBTTtFQUNMRixNQUFNLENBQUNDLE9BQU8sR0FBR0MsT0FBTyxDQUFDLCtCQUErQixDQUFDO0FBQzNEIn0=
}).call(this,require("Xp6JUx"))
},{"./cjs/react-is.development.js":9,"./cjs/react-is.production.min.js":10,"Xp6JUx":2}],12:[function(require,module,exports){
(function (process){
/**
 * @license React
 * react.development.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

if (process.env.NODE_ENV !== "production") {
  (function () {
    'use strict';

    /* global __REACT_DEVTOOLS_GLOBAL_HOOK__ */
    if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' && typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart === 'function') {
      __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(new Error());
    }
    var ReactVersion = '18.2.0';

    // ATTENTION
    // When adding new symbols to this file,
    // Please consider also adding to 'react-devtools-shared/src/backend/ReactSymbols'
    // The Symbol used to tag the ReactElement-like types.
    var REACT_ELEMENT_TYPE = Symbol.for('react.element');
    var REACT_PORTAL_TYPE = Symbol.for('react.portal');
    var REACT_FRAGMENT_TYPE = Symbol.for('react.fragment');
    var REACT_STRICT_MODE_TYPE = Symbol.for('react.strict_mode');
    var REACT_PROFILER_TYPE = Symbol.for('react.profiler');
    var REACT_PROVIDER_TYPE = Symbol.for('react.provider');
    var REACT_CONTEXT_TYPE = Symbol.for('react.context');
    var REACT_FORWARD_REF_TYPE = Symbol.for('react.forward_ref');
    var REACT_SUSPENSE_TYPE = Symbol.for('react.suspense');
    var REACT_SUSPENSE_LIST_TYPE = Symbol.for('react.suspense_list');
    var REACT_MEMO_TYPE = Symbol.for('react.memo');
    var REACT_LAZY_TYPE = Symbol.for('react.lazy');
    var REACT_OFFSCREEN_TYPE = Symbol.for('react.offscreen');
    var MAYBE_ITERATOR_SYMBOL = Symbol.iterator;
    var FAUX_ITERATOR_SYMBOL = '@@iterator';
    function getIteratorFn(maybeIterable) {
      if (maybeIterable === null || typeof maybeIterable !== 'object') {
        return null;
      }
      var maybeIterator = MAYBE_ITERATOR_SYMBOL && maybeIterable[MAYBE_ITERATOR_SYMBOL] || maybeIterable[FAUX_ITERATOR_SYMBOL];
      if (typeof maybeIterator === 'function') {
        return maybeIterator;
      }
      return null;
    }

    /**
     * Keeps track of the current dispatcher.
     */
    var ReactCurrentDispatcher = {
      /**
       * @internal
       * @type {ReactComponent}
       */
      current: null
    };

    /**
     * Keeps track of the current batch's configuration such as how long an update
     * should suspend for if it needs to.
     */
    var ReactCurrentBatchConfig = {
      transition: null
    };
    var ReactCurrentActQueue = {
      current: null,
      // Used to reproduce behavior of `batchedUpdates` in legacy mode.
      isBatchingLegacy: false,
      didScheduleLegacyUpdate: false
    };

    /**
     * Keeps track of the current owner.
     *
     * The current owner is the component who should own any components that are
     * currently being constructed.
     */
    var ReactCurrentOwner = {
      /**
       * @internal
       * @type {ReactComponent}
       */
      current: null
    };
    var ReactDebugCurrentFrame = {};
    var currentExtraStackFrame = null;
    function setExtraStackFrame(stack) {
      {
        currentExtraStackFrame = stack;
      }
    }
    {
      ReactDebugCurrentFrame.setExtraStackFrame = function (stack) {
        {
          currentExtraStackFrame = stack;
        }
      }; // Stack implementation injected by the current renderer.

      ReactDebugCurrentFrame.getCurrentStack = null;
      ReactDebugCurrentFrame.getStackAddendum = function () {
        var stack = ''; // Add an extra top frame while an element is being validated

        if (currentExtraStackFrame) {
          stack += currentExtraStackFrame;
        } // Delegate to the injected renderer-specific implementation

        var impl = ReactDebugCurrentFrame.getCurrentStack;
        if (impl) {
          stack += impl() || '';
        }
        return stack;
      };
    }

    // -----------------------------------------------------------------------------

    var enableScopeAPI = false; // Experimental Create Event Handle API.
    var enableCacheElement = false;
    var enableTransitionTracing = false; // No known bugs, but needs performance testing

    var enableLegacyHidden = false; // Enables unstable_avoidThisFallback feature in Fiber
    // stuff. Intended to enable React core members to more easily debug scheduling
    // issues in DEV builds.

    var enableDebugTracing = false; // Track which Fiber(s) schedule render work.

    var ReactSharedInternals = {
      ReactCurrentDispatcher: ReactCurrentDispatcher,
      ReactCurrentBatchConfig: ReactCurrentBatchConfig,
      ReactCurrentOwner: ReactCurrentOwner
    };
    {
      ReactSharedInternals.ReactDebugCurrentFrame = ReactDebugCurrentFrame;
      ReactSharedInternals.ReactCurrentActQueue = ReactCurrentActQueue;
    }

    // by calls to these methods by a Babel plugin.
    //
    // In PROD (or in packages without access to React internals),
    // they are left as they are instead.

    function warn(format) {
      {
        {
          for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
            args[_key - 1] = arguments[_key];
          }
          printWarning('warn', format, args);
        }
      }
    }
    function error(format) {
      {
        {
          for (var _len2 = arguments.length, args = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
            args[_key2 - 1] = arguments[_key2];
          }
          printWarning('error', format, args);
        }
      }
    }
    function printWarning(level, format, args) {
      // When changing this logic, you might want to also
      // update consoleWithStackDev.www.js as well.
      {
        var ReactDebugCurrentFrame = ReactSharedInternals.ReactDebugCurrentFrame;
        var stack = ReactDebugCurrentFrame.getStackAddendum();
        if (stack !== '') {
          format += '%s';
          args = args.concat([stack]);
        } // eslint-disable-next-line react-internal/safe-string-coercion

        var argsWithFormat = args.map(function (item) {
          return String(item);
        }); // Careful: RN currently depends on this prefix

        argsWithFormat.unshift('Warning: ' + format); // We intentionally don't use spread (or .apply) directly because it
        // breaks IE9: https://github.com/facebook/react/issues/13610
        // eslint-disable-next-line react-internal/no-production-logging

        Function.prototype.apply.call(console[level], console, argsWithFormat);
      }
    }
    var didWarnStateUpdateForUnmountedComponent = {};
    function warnNoop(publicInstance, callerName) {
      {
        var _constructor = publicInstance.constructor;
        var componentName = _constructor && (_constructor.displayName || _constructor.name) || 'ReactClass';
        var warningKey = componentName + "." + callerName;
        if (didWarnStateUpdateForUnmountedComponent[warningKey]) {
          return;
        }
        error("Can't call %s on a component that is not yet mounted. " + 'This is a no-op, but it might indicate a bug in your application. ' + 'Instead, assign to `this.state` directly or define a `state = {};` ' + 'class property with the desired state in the %s component.', callerName, componentName);
        didWarnStateUpdateForUnmountedComponent[warningKey] = true;
      }
    }
    /**
     * This is the abstract API for an update queue.
     */

    var ReactNoopUpdateQueue = {
      /**
       * Checks whether or not this composite component is mounted.
       * @param {ReactClass} publicInstance The instance we want to test.
       * @return {boolean} True if mounted, false otherwise.
       * @protected
       * @final
       */
      isMounted: function (publicInstance) {
        return false;
      },
      /**
       * Forces an update. This should only be invoked when it is known with
       * certainty that we are **not** in a DOM transaction.
       *
       * You may want to call this when you know that some deeper aspect of the
       * component's state has changed but `setState` was not called.
       *
       * This will not invoke `shouldComponentUpdate`, but it will invoke
       * `componentWillUpdate` and `componentDidUpdate`.
       *
       * @param {ReactClass} publicInstance The instance that should rerender.
       * @param {?function} callback Called after component is updated.
       * @param {?string} callerName name of the calling function in the public API.
       * @internal
       */
      enqueueForceUpdate: function (publicInstance, callback, callerName) {
        warnNoop(publicInstance, 'forceUpdate');
      },
      /**
       * Replaces all of the state. Always use this or `setState` to mutate state.
       * You should treat `this.state` as immutable.
       *
       * There is no guarantee that `this.state` will be immediately updated, so
       * accessing `this.state` after calling this method may return the old value.
       *
       * @param {ReactClass} publicInstance The instance that should rerender.
       * @param {object} completeState Next state.
       * @param {?function} callback Called after component is updated.
       * @param {?string} callerName name of the calling function in the public API.
       * @internal
       */
      enqueueReplaceState: function (publicInstance, completeState, callback, callerName) {
        warnNoop(publicInstance, 'replaceState');
      },
      /**
       * Sets a subset of the state. This only exists because _pendingState is
       * internal. This provides a merging strategy that is not available to deep
       * properties which is confusing. TODO: Expose pendingState or don't use it
       * during the merge.
       *
       * @param {ReactClass} publicInstance The instance that should rerender.
       * @param {object} partialState Next partial state to be merged with state.
       * @param {?function} callback Called after component is updated.
       * @param {?string} Name of the calling function in the public API.
       * @internal
       */
      enqueueSetState: function (publicInstance, partialState, callback, callerName) {
        warnNoop(publicInstance, 'setState');
      }
    };
    var assign = Object.assign;
    var emptyObject = {};
    {
      Object.freeze(emptyObject);
    }
    /**
     * Base class helpers for the updating state of a component.
     */

    function Component(props, context, updater) {
      this.props = props;
      this.context = context; // If a component has string refs, we will assign a different object later.

      this.refs = emptyObject; // We initialize the default updater but the real one gets injected by the
      // renderer.

      this.updater = updater || ReactNoopUpdateQueue;
    }
    Component.prototype.isReactComponent = {};
    /**
     * Sets a subset of the state. Always use this to mutate
     * state. You should treat `this.state` as immutable.
     *
     * There is no guarantee that `this.state` will be immediately updated, so
     * accessing `this.state` after calling this method may return the old value.
     *
     * There is no guarantee that calls to `setState` will run synchronously,
     * as they may eventually be batched together.  You can provide an optional
     * callback that will be executed when the call to setState is actually
     * completed.
     *
     * When a function is provided to setState, it will be called at some point in
     * the future (not synchronously). It will be called with the up to date
     * component arguments (state, props, context). These values can be different
     * from this.* because your function may be called after receiveProps but before
     * shouldComponentUpdate, and this new state, props, and context will not yet be
     * assigned to this.
     *
     * @param {object|function} partialState Next partial state or function to
     *        produce next partial state to be merged with current state.
     * @param {?function} callback Called after state is updated.
     * @final
     * @protected
     */

    Component.prototype.setState = function (partialState, callback) {
      if (typeof partialState !== 'object' && typeof partialState !== 'function' && partialState != null) {
        throw new Error('setState(...): takes an object of state variables to update or a ' + 'function which returns an object of state variables.');
      }
      this.updater.enqueueSetState(this, partialState, callback, 'setState');
    };
    /**
     * Forces an update. This should only be invoked when it is known with
     * certainty that we are **not** in a DOM transaction.
     *
     * You may want to call this when you know that some deeper aspect of the
     * component's state has changed but `setState` was not called.
     *
     * This will not invoke `shouldComponentUpdate`, but it will invoke
     * `componentWillUpdate` and `componentDidUpdate`.
     *
     * @param {?function} callback Called after update is complete.
     * @final
     * @protected
     */

    Component.prototype.forceUpdate = function (callback) {
      this.updater.enqueueForceUpdate(this, callback, 'forceUpdate');
    };
    /**
     * Deprecated APIs. These APIs used to exist on classic React classes but since
     * we would like to deprecate them, we're not going to move them over to this
     * modern base class. Instead, we define a getter that warns if it's accessed.
     */

    {
      var deprecatedAPIs = {
        isMounted: ['isMounted', 'Instead, make sure to clean up subscriptions and pending requests in ' + 'componentWillUnmount to prevent memory leaks.'],
        replaceState: ['replaceState', 'Refactor your code to use setState instead (see ' + 'https://github.com/facebook/react/issues/3236).']
      };
      var defineDeprecationWarning = function (methodName, info) {
        Object.defineProperty(Component.prototype, methodName, {
          get: function () {
            warn('%s(...) is deprecated in plain JavaScript React classes. %s', info[0], info[1]);
            return undefined;
          }
        });
      };
      for (var fnName in deprecatedAPIs) {
        if (deprecatedAPIs.hasOwnProperty(fnName)) {
          defineDeprecationWarning(fnName, deprecatedAPIs[fnName]);
        }
      }
    }
    function ComponentDummy() {}
    ComponentDummy.prototype = Component.prototype;
    /**
     * Convenience component with default shallow equality check for sCU.
     */

    function PureComponent(props, context, updater) {
      this.props = props;
      this.context = context; // If a component has string refs, we will assign a different object later.

      this.refs = emptyObject;
      this.updater = updater || ReactNoopUpdateQueue;
    }
    var pureComponentPrototype = PureComponent.prototype = new ComponentDummy();
    pureComponentPrototype.constructor = PureComponent; // Avoid an extra prototype jump for these methods.

    assign(pureComponentPrototype, Component.prototype);
    pureComponentPrototype.isPureReactComponent = true;

    // an immutable object with a single mutable value
    function createRef() {
      var refObject = {
        current: null
      };
      {
        Object.seal(refObject);
      }
      return refObject;
    }
    var isArrayImpl = Array.isArray; // eslint-disable-next-line no-redeclare

    function isArray(a) {
      return isArrayImpl(a);
    }

    /*
     * The `'' + value` pattern (used in in perf-sensitive code) throws for Symbol
     * and Temporal.* types. See https://github.com/facebook/react/pull/22064.
     *
     * The functions in this module will throw an easier-to-understand,
     * easier-to-debug exception with a clear errors message message explaining the
     * problem. (Instead of a confusing exception thrown inside the implementation
     * of the `value` object).
     */
    // $FlowFixMe only called in DEV, so void return is not possible.
    function typeName(value) {
      {
        // toStringTag is needed for namespaced types like Temporal.Instant
        var hasToStringTag = typeof Symbol === 'function' && Symbol.toStringTag;
        var type = hasToStringTag && value[Symbol.toStringTag] || value.constructor.name || 'Object';
        return type;
      }
    } // $FlowFixMe only called in DEV, so void return is not possible.

    function willCoercionThrow(value) {
      {
        try {
          testStringCoercion(value);
          return false;
        } catch (e) {
          return true;
        }
      }
    }
    function testStringCoercion(value) {
      // If you ended up here by following an exception call stack, here's what's
      // happened: you supplied an object or symbol value to React (as a prop, key,
      // DOM attribute, CSS property, string ref, etc.) and when React tried to
      // coerce it to a string using `'' + value`, an exception was thrown.
      //
      // The most common types that will cause this exception are `Symbol` instances
      // and Temporal objects like `Temporal.Instant`. But any object that has a
      // `valueOf` or `[Symbol.toPrimitive]` method that throws will also cause this
      // exception. (Library authors do this to prevent users from using built-in
      // numeric operators like `+` or comparison operators like `>=` because custom
      // methods are needed to perform accurate arithmetic or comparison.)
      //
      // To fix the problem, coerce this object or symbol value to a string before
      // passing it to React. The most reliable way is usually `String(value)`.
      //
      // To find which value is throwing, check the browser or debugger console.
      // Before this exception was thrown, there should be `console.error` output
      // that shows the type (Symbol, Temporal.PlainDate, etc.) that caused the
      // problem and how that type was used: key, atrribute, input value prop, etc.
      // In most cases, this console output also shows the component and its
      // ancestor components where the exception happened.
      //
      // eslint-disable-next-line react-internal/safe-string-coercion
      return '' + value;
    }
    function checkKeyStringCoercion(value) {
      {
        if (willCoercionThrow(value)) {
          error('The provided key is an unsupported type %s.' + ' This value must be coerced to a string before before using it here.', typeName(value));
          return testStringCoercion(value); // throw (to help callers find troubleshooting comments)
        }
      }
    }

    function getWrappedName(outerType, innerType, wrapperName) {
      var displayName = outerType.displayName;
      if (displayName) {
        return displayName;
      }
      var functionName = innerType.displayName || innerType.name || '';
      return functionName !== '' ? wrapperName + "(" + functionName + ")" : wrapperName;
    } // Keep in sync with react-reconciler/getComponentNameFromFiber

    function getContextName(type) {
      return type.displayName || 'Context';
    } // Note that the reconciler package should generally prefer to use getComponentNameFromFiber() instead.

    function getComponentNameFromType(type) {
      if (type == null) {
        // Host root, text node or just invalid type.
        return null;
      }
      {
        if (typeof type.tag === 'number') {
          error('Received an unexpected object in getComponentNameFromType(). ' + 'This is likely a bug in React. Please file an issue.');
        }
      }
      if (typeof type === 'function') {
        return type.displayName || type.name || null;
      }
      if (typeof type === 'string') {
        return type;
      }
      switch (type) {
        case REACT_FRAGMENT_TYPE:
          return 'Fragment';
        case REACT_PORTAL_TYPE:
          return 'Portal';
        case REACT_PROFILER_TYPE:
          return 'Profiler';
        case REACT_STRICT_MODE_TYPE:
          return 'StrictMode';
        case REACT_SUSPENSE_TYPE:
          return 'Suspense';
        case REACT_SUSPENSE_LIST_TYPE:
          return 'SuspenseList';
      }
      if (typeof type === 'object') {
        switch (type.$$typeof) {
          case REACT_CONTEXT_TYPE:
            var context = type;
            return getContextName(context) + '.Consumer';
          case REACT_PROVIDER_TYPE:
            var provider = type;
            return getContextName(provider._context) + '.Provider';
          case REACT_FORWARD_REF_TYPE:
            return getWrappedName(type, type.render, 'ForwardRef');
          case REACT_MEMO_TYPE:
            var outerName = type.displayName || null;
            if (outerName !== null) {
              return outerName;
            }
            return getComponentNameFromType(type.type) || 'Memo';
          case REACT_LAZY_TYPE:
            {
              var lazyComponent = type;
              var payload = lazyComponent._payload;
              var init = lazyComponent._init;
              try {
                return getComponentNameFromType(init(payload));
              } catch (x) {
                return null;
              }
            }

          // eslint-disable-next-line no-fallthrough
        }
      }

      return null;
    }
    var hasOwnProperty = Object.prototype.hasOwnProperty;
    var RESERVED_PROPS = {
      key: true,
      ref: true,
      __self: true,
      __source: true
    };
    var specialPropKeyWarningShown, specialPropRefWarningShown, didWarnAboutStringRefs;
    {
      didWarnAboutStringRefs = {};
    }
    function hasValidRef(config) {
      {
        if (hasOwnProperty.call(config, 'ref')) {
          var getter = Object.getOwnPropertyDescriptor(config, 'ref').get;
          if (getter && getter.isReactWarning) {
            return false;
          }
        }
      }
      return config.ref !== undefined;
    }
    function hasValidKey(config) {
      {
        if (hasOwnProperty.call(config, 'key')) {
          var getter = Object.getOwnPropertyDescriptor(config, 'key').get;
          if (getter && getter.isReactWarning) {
            return false;
          }
        }
      }
      return config.key !== undefined;
    }
    function defineKeyPropWarningGetter(props, displayName) {
      var warnAboutAccessingKey = function () {
        {
          if (!specialPropKeyWarningShown) {
            specialPropKeyWarningShown = true;
            error('%s: `key` is not a prop. Trying to access it will result ' + 'in `undefined` being returned. If you need to access the same ' + 'value within the child component, you should pass it as a different ' + 'prop. (https://reactjs.org/link/special-props)', displayName);
          }
        }
      };
      warnAboutAccessingKey.isReactWarning = true;
      Object.defineProperty(props, 'key', {
        get: warnAboutAccessingKey,
        configurable: true
      });
    }
    function defineRefPropWarningGetter(props, displayName) {
      var warnAboutAccessingRef = function () {
        {
          if (!specialPropRefWarningShown) {
            specialPropRefWarningShown = true;
            error('%s: `ref` is not a prop. Trying to access it will result ' + 'in `undefined` being returned. If you need to access the same ' + 'value within the child component, you should pass it as a different ' + 'prop. (https://reactjs.org/link/special-props)', displayName);
          }
        }
      };
      warnAboutAccessingRef.isReactWarning = true;
      Object.defineProperty(props, 'ref', {
        get: warnAboutAccessingRef,
        configurable: true
      });
    }
    function warnIfStringRefCannotBeAutoConverted(config) {
      {
        if (typeof config.ref === 'string' && ReactCurrentOwner.current && config.__self && ReactCurrentOwner.current.stateNode !== config.__self) {
          var componentName = getComponentNameFromType(ReactCurrentOwner.current.type);
          if (!didWarnAboutStringRefs[componentName]) {
            error('Component "%s" contains the string ref "%s". ' + 'Support for string refs will be removed in a future major release. ' + 'This case cannot be automatically converted to an arrow function. ' + 'We ask you to manually fix this case by using useRef() or createRef() instead. ' + 'Learn more about using refs safely here: ' + 'https://reactjs.org/link/strict-mode-string-ref', componentName, config.ref);
            didWarnAboutStringRefs[componentName] = true;
          }
        }
      }
    }
    /**
     * Factory method to create a new React element. This no longer adheres to
     * the class pattern, so do not use new to call it. Also, instanceof check
     * will not work. Instead test $$typeof field against Symbol.for('react.element') to check
     * if something is a React Element.
     *
     * @param {*} type
     * @param {*} props
     * @param {*} key
     * @param {string|object} ref
     * @param {*} owner
     * @param {*} self A *temporary* helper to detect places where `this` is
     * different from the `owner` when React.createElement is called, so that we
     * can warn. We want to get rid of owner and replace string `ref`s with arrow
     * functions, and as long as `this` and owner are the same, there will be no
     * change in behavior.
     * @param {*} source An annotation object (added by a transpiler or otherwise)
     * indicating filename, line number, and/or other information.
     * @internal
     */

    var ReactElement = function (type, key, ref, self, source, owner, props) {
      var element = {
        // This tag allows us to uniquely identify this as a React Element
        $$typeof: REACT_ELEMENT_TYPE,
        // Built-in properties that belong on the element
        type: type,
        key: key,
        ref: ref,
        props: props,
        // Record the component responsible for creating this element.
        _owner: owner
      };
      {
        // The validation flag is currently mutative. We put it on
        // an external backing store so that we can freeze the whole object.
        // This can be replaced with a WeakMap once they are implemented in
        // commonly used development environments.
        element._store = {}; // To make comparing ReactElements easier for testing purposes, we make
        // the validation flag non-enumerable (where possible, which should
        // include every environment we run tests in), so the test framework
        // ignores it.

        Object.defineProperty(element._store, 'validated', {
          configurable: false,
          enumerable: false,
          writable: true,
          value: false
        }); // self and source are DEV only properties.

        Object.defineProperty(element, '_self', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: self
        }); // Two elements created in two different places should be considered
        // equal for testing purposes and therefore we hide it from enumeration.

        Object.defineProperty(element, '_source', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: source
        });
        if (Object.freeze) {
          Object.freeze(element.props);
          Object.freeze(element);
        }
      }
      return element;
    };
    /**
     * Create and return a new ReactElement of the given type.
     * See https://reactjs.org/docs/react-api.html#createelement
     */

    function createElement(type, config, children) {
      var propName; // Reserved names are extracted

      var props = {};
      var key = null;
      var ref = null;
      var self = null;
      var source = null;
      if (config != null) {
        if (hasValidRef(config)) {
          ref = config.ref;
          {
            warnIfStringRefCannotBeAutoConverted(config);
          }
        }
        if (hasValidKey(config)) {
          {
            checkKeyStringCoercion(config.key);
          }
          key = '' + config.key;
        }
        self = config.__self === undefined ? null : config.__self;
        source = config.__source === undefined ? null : config.__source; // Remaining properties are added to a new props object

        for (propName in config) {
          if (hasOwnProperty.call(config, propName) && !RESERVED_PROPS.hasOwnProperty(propName)) {
            props[propName] = config[propName];
          }
        }
      } // Children can be more than one argument, and those are transferred onto
      // the newly allocated props object.

      var childrenLength = arguments.length - 2;
      if (childrenLength === 1) {
        props.children = children;
      } else if (childrenLength > 1) {
        var childArray = Array(childrenLength);
        for (var i = 0; i < childrenLength; i++) {
          childArray[i] = arguments[i + 2];
        }
        {
          if (Object.freeze) {
            Object.freeze(childArray);
          }
        }
        props.children = childArray;
      } // Resolve default props

      if (type && type.defaultProps) {
        var defaultProps = type.defaultProps;
        for (propName in defaultProps) {
          if (props[propName] === undefined) {
            props[propName] = defaultProps[propName];
          }
        }
      }
      {
        if (key || ref) {
          var displayName = typeof type === 'function' ? type.displayName || type.name || 'Unknown' : type;
          if (key) {
            defineKeyPropWarningGetter(props, displayName);
          }
          if (ref) {
            defineRefPropWarningGetter(props, displayName);
          }
        }
      }
      return ReactElement(type, key, ref, self, source, ReactCurrentOwner.current, props);
    }
    function cloneAndReplaceKey(oldElement, newKey) {
      var newElement = ReactElement(oldElement.type, newKey, oldElement.ref, oldElement._self, oldElement._source, oldElement._owner, oldElement.props);
      return newElement;
    }
    /**
     * Clone and return a new ReactElement using element as the starting point.
     * See https://reactjs.org/docs/react-api.html#cloneelement
     */

    function cloneElement(element, config, children) {
      if (element === null || element === undefined) {
        throw new Error("React.cloneElement(...): The argument must be a React element, but you passed " + element + ".");
      }
      var propName; // Original props are copied

      var props = assign({}, element.props); // Reserved names are extracted

      var key = element.key;
      var ref = element.ref; // Self is preserved since the owner is preserved.

      var self = element._self; // Source is preserved since cloneElement is unlikely to be targeted by a
      // transpiler, and the original source is probably a better indicator of the
      // true owner.

      var source = element._source; // Owner will be preserved, unless ref is overridden

      var owner = element._owner;
      if (config != null) {
        if (hasValidRef(config)) {
          // Silently steal the ref from the parent.
          ref = config.ref;
          owner = ReactCurrentOwner.current;
        }
        if (hasValidKey(config)) {
          {
            checkKeyStringCoercion(config.key);
          }
          key = '' + config.key;
        } // Remaining properties override existing props

        var defaultProps;
        if (element.type && element.type.defaultProps) {
          defaultProps = element.type.defaultProps;
        }
        for (propName in config) {
          if (hasOwnProperty.call(config, propName) && !RESERVED_PROPS.hasOwnProperty(propName)) {
            if (config[propName] === undefined && defaultProps !== undefined) {
              // Resolve default props
              props[propName] = defaultProps[propName];
            } else {
              props[propName] = config[propName];
            }
          }
        }
      } // Children can be more than one argument, and those are transferred onto
      // the newly allocated props object.

      var childrenLength = arguments.length - 2;
      if (childrenLength === 1) {
        props.children = children;
      } else if (childrenLength > 1) {
        var childArray = Array(childrenLength);
        for (var i = 0; i < childrenLength; i++) {
          childArray[i] = arguments[i + 2];
        }
        props.children = childArray;
      }
      return ReactElement(element.type, key, ref, self, source, owner, props);
    }
    /**
     * Verifies the object is a ReactElement.
     * See https://reactjs.org/docs/react-api.html#isvalidelement
     * @param {?object} object
     * @return {boolean} True if `object` is a ReactElement.
     * @final
     */

    function isValidElement(object) {
      return typeof object === 'object' && object !== null && object.$$typeof === REACT_ELEMENT_TYPE;
    }
    var SEPARATOR = '.';
    var SUBSEPARATOR = ':';
    /**
     * Escape and wrap key so it is safe to use as a reactid
     *
     * @param {string} key to be escaped.
     * @return {string} the escaped key.
     */

    function escape(key) {
      var escapeRegex = /[=:]/g;
      var escaperLookup = {
        '=': '=0',
        ':': '=2'
      };
      var escapedString = key.replace(escapeRegex, function (match) {
        return escaperLookup[match];
      });
      return '$' + escapedString;
    }
    /**
     * TODO: Test that a single child and an array with one item have the same key
     * pattern.
     */

    var didWarnAboutMaps = false;
    var userProvidedKeyEscapeRegex = /\/+/g;
    function escapeUserProvidedKey(text) {
      return text.replace(userProvidedKeyEscapeRegex, '$&/');
    }
    /**
     * Generate a key string that identifies a element within a set.
     *
     * @param {*} element A element that could contain a manual key.
     * @param {number} index Index that is used if a manual key is not provided.
     * @return {string}
     */

    function getElementKey(element, index) {
      // Do some typechecking here since we call this blindly. We want to ensure
      // that we don't block potential future ES APIs.
      if (typeof element === 'object' && element !== null && element.key != null) {
        // Explicit key
        {
          checkKeyStringCoercion(element.key);
        }
        return escape('' + element.key);
      } // Implicit key determined by the index in the set

      return index.toString(36);
    }
    function mapIntoArray(children, array, escapedPrefix, nameSoFar, callback) {
      var type = typeof children;
      if (type === 'undefined' || type === 'boolean') {
        // All of the above are perceived as null.
        children = null;
      }
      var invokeCallback = false;
      if (children === null) {
        invokeCallback = true;
      } else {
        switch (type) {
          case 'string':
          case 'number':
            invokeCallback = true;
            break;
          case 'object':
            switch (children.$$typeof) {
              case REACT_ELEMENT_TYPE:
              case REACT_PORTAL_TYPE:
                invokeCallback = true;
            }
        }
      }
      if (invokeCallback) {
        var _child = children;
        var mappedChild = callback(_child); // If it's the only child, treat the name as if it was wrapped in an array
        // so that it's consistent if the number of children grows:

        var childKey = nameSoFar === '' ? SEPARATOR + getElementKey(_child, 0) : nameSoFar;
        if (isArray(mappedChild)) {
          var escapedChildKey = '';
          if (childKey != null) {
            escapedChildKey = escapeUserProvidedKey(childKey) + '/';
          }
          mapIntoArray(mappedChild, array, escapedChildKey, '', function (c) {
            return c;
          });
        } else if (mappedChild != null) {
          if (isValidElement(mappedChild)) {
            {
              // The `if` statement here prevents auto-disabling of the safe
              // coercion ESLint rule, so we must manually disable it below.
              // $FlowFixMe Flow incorrectly thinks React.Portal doesn't have a key
              if (mappedChild.key && (!_child || _child.key !== mappedChild.key)) {
                checkKeyStringCoercion(mappedChild.key);
              }
            }
            mappedChild = cloneAndReplaceKey(mappedChild,
            // Keep both the (mapped) and old keys if they differ, just as
            // traverseAllChildren used to do for objects as children
            escapedPrefix + (
            // $FlowFixMe Flow incorrectly thinks React.Portal doesn't have a key
            mappedChild.key && (!_child || _child.key !== mappedChild.key) ?
            // $FlowFixMe Flow incorrectly thinks existing element's key can be a number
            // eslint-disable-next-line react-internal/safe-string-coercion
            escapeUserProvidedKey('' + mappedChild.key) + '/' : '') + childKey);
          }
          array.push(mappedChild);
        }
        return 1;
      }
      var child;
      var nextName;
      var subtreeCount = 0; // Count of children found in the current subtree.

      var nextNamePrefix = nameSoFar === '' ? SEPARATOR : nameSoFar + SUBSEPARATOR;
      if (isArray(children)) {
        for (var i = 0; i < children.length; i++) {
          child = children[i];
          nextName = nextNamePrefix + getElementKey(child, i);
          subtreeCount += mapIntoArray(child, array, escapedPrefix, nextName, callback);
        }
      } else {
        var iteratorFn = getIteratorFn(children);
        if (typeof iteratorFn === 'function') {
          var iterableChildren = children;
          {
            // Warn about using Maps as children
            if (iteratorFn === iterableChildren.entries) {
              if (!didWarnAboutMaps) {
                warn('Using Maps as children is not supported. ' + 'Use an array of keyed ReactElements instead.');
              }
              didWarnAboutMaps = true;
            }
          }
          var iterator = iteratorFn.call(iterableChildren);
          var step;
          var ii = 0;
          while (!(step = iterator.next()).done) {
            child = step.value;
            nextName = nextNamePrefix + getElementKey(child, ii++);
            subtreeCount += mapIntoArray(child, array, escapedPrefix, nextName, callback);
          }
        } else if (type === 'object') {
          // eslint-disable-next-line react-internal/safe-string-coercion
          var childrenString = String(children);
          throw new Error("Objects are not valid as a React child (found: " + (childrenString === '[object Object]' ? 'object with keys {' + Object.keys(children).join(', ') + '}' : childrenString) + "). " + 'If you meant to render a collection of children, use an array ' + 'instead.');
        }
      }
      return subtreeCount;
    }

    /**
     * Maps children that are typically specified as `props.children`.
     *
     * See https://reactjs.org/docs/react-api.html#reactchildrenmap
     *
     * The provided mapFunction(child, index) will be called for each
     * leaf child.
     *
     * @param {?*} children Children tree container.
     * @param {function(*, int)} func The map function.
     * @param {*} context Context for mapFunction.
     * @return {object} Object containing the ordered map of results.
     */
    function mapChildren(children, func, context) {
      if (children == null) {
        return children;
      }
      var result = [];
      var count = 0;
      mapIntoArray(children, result, '', '', function (child) {
        return func.call(context, child, count++);
      });
      return result;
    }
    /**
     * Count the number of children that are typically specified as
     * `props.children`.
     *
     * See https://reactjs.org/docs/react-api.html#reactchildrencount
     *
     * @param {?*} children Children tree container.
     * @return {number} The number of children.
     */

    function countChildren(children) {
      var n = 0;
      mapChildren(children, function () {
        n++; // Don't return anything
      });

      return n;
    }

    /**
     * Iterates through children that are typically specified as `props.children`.
     *
     * See https://reactjs.org/docs/react-api.html#reactchildrenforeach
     *
     * The provided forEachFunc(child, index) will be called for each
     * leaf child.
     *
     * @param {?*} children Children tree container.
     * @param {function(*, int)} forEachFunc
     * @param {*} forEachContext Context for forEachContext.
     */
    function forEachChildren(children, forEachFunc, forEachContext) {
      mapChildren(children, function () {
        forEachFunc.apply(this, arguments); // Don't return anything.
      }, forEachContext);
    }
    /**
     * Flatten a children object (typically specified as `props.children`) and
     * return an array with appropriately re-keyed children.
     *
     * See https://reactjs.org/docs/react-api.html#reactchildrentoarray
     */

    function toArray(children) {
      return mapChildren(children, function (child) {
        return child;
      }) || [];
    }
    /**
     * Returns the first child in a collection of children and verifies that there
     * is only one child in the collection.
     *
     * See https://reactjs.org/docs/react-api.html#reactchildrenonly
     *
     * The current implementation of this function assumes that a single child gets
     * passed without a wrapper, but the purpose of this helper function is to
     * abstract away the particular structure of children.
     *
     * @param {?object} children Child collection structure.
     * @return {ReactElement} The first and only `ReactElement` contained in the
     * structure.
     */

    function onlyChild(children) {
      if (!isValidElement(children)) {
        throw new Error('React.Children.only expected to receive a single React element child.');
      }
      return children;
    }
    function createContext(defaultValue) {
      // TODO: Second argument used to be an optional `calculateChangedBits`
      // function. Warn to reserve for future use?
      var context = {
        $$typeof: REACT_CONTEXT_TYPE,
        // As a workaround to support multiple concurrent renderers, we categorize
        // some renderers as primary and others as secondary. We only expect
        // there to be two concurrent renderers at most: React Native (primary) and
        // Fabric (secondary); React DOM (primary) and React ART (secondary).
        // Secondary renderers store their context values on separate fields.
        _currentValue: defaultValue,
        _currentValue2: defaultValue,
        // Used to track how many concurrent renderers this context currently
        // supports within in a single renderer. Such as parallel server rendering.
        _threadCount: 0,
        // These are circular
        Provider: null,
        Consumer: null,
        // Add these to use same hidden class in VM as ServerContext
        _defaultValue: null,
        _globalName: null
      };
      context.Provider = {
        $$typeof: REACT_PROVIDER_TYPE,
        _context: context
      };
      var hasWarnedAboutUsingNestedContextConsumers = false;
      var hasWarnedAboutUsingConsumerProvider = false;
      var hasWarnedAboutDisplayNameOnConsumer = false;
      {
        // A separate object, but proxies back to the original context object for
        // backwards compatibility. It has a different $$typeof, so we can properly
        // warn for the incorrect usage of Context as a Consumer.
        var Consumer = {
          $$typeof: REACT_CONTEXT_TYPE,
          _context: context
        }; // $FlowFixMe: Flow complains about not setting a value, which is intentional here

        Object.defineProperties(Consumer, {
          Provider: {
            get: function () {
              if (!hasWarnedAboutUsingConsumerProvider) {
                hasWarnedAboutUsingConsumerProvider = true;
                error('Rendering <Context.Consumer.Provider> is not supported and will be removed in ' + 'a future major release. Did you mean to render <Context.Provider> instead?');
              }
              return context.Provider;
            },
            set: function (_Provider) {
              context.Provider = _Provider;
            }
          },
          _currentValue: {
            get: function () {
              return context._currentValue;
            },
            set: function (_currentValue) {
              context._currentValue = _currentValue;
            }
          },
          _currentValue2: {
            get: function () {
              return context._currentValue2;
            },
            set: function (_currentValue2) {
              context._currentValue2 = _currentValue2;
            }
          },
          _threadCount: {
            get: function () {
              return context._threadCount;
            },
            set: function (_threadCount) {
              context._threadCount = _threadCount;
            }
          },
          Consumer: {
            get: function () {
              if (!hasWarnedAboutUsingNestedContextConsumers) {
                hasWarnedAboutUsingNestedContextConsumers = true;
                error('Rendering <Context.Consumer.Consumer> is not supported and will be removed in ' + 'a future major release. Did you mean to render <Context.Consumer> instead?');
              }
              return context.Consumer;
            }
          },
          displayName: {
            get: function () {
              return context.displayName;
            },
            set: function (displayName) {
              if (!hasWarnedAboutDisplayNameOnConsumer) {
                warn('Setting `displayName` on Context.Consumer has no effect. ' + "You should set it directly on the context with Context.displayName = '%s'.", displayName);
                hasWarnedAboutDisplayNameOnConsumer = true;
              }
            }
          }
        }); // $FlowFixMe: Flow complains about missing properties because it doesn't understand defineProperty

        context.Consumer = Consumer;
      }
      {
        context._currentRenderer = null;
        context._currentRenderer2 = null;
      }
      return context;
    }
    var Uninitialized = -1;
    var Pending = 0;
    var Resolved = 1;
    var Rejected = 2;
    function lazyInitializer(payload) {
      if (payload._status === Uninitialized) {
        var ctor = payload._result;
        var thenable = ctor(); // Transition to the next state.
        // This might throw either because it's missing or throws. If so, we treat it
        // as still uninitialized and try again next time. Which is the same as what
        // happens if the ctor or any wrappers processing the ctor throws. This might
        // end up fixing it if the resolution was a concurrency bug.

        thenable.then(function (moduleObject) {
          if (payload._status === Pending || payload._status === Uninitialized) {
            // Transition to the next state.
            var resolved = payload;
            resolved._status = Resolved;
            resolved._result = moduleObject;
          }
        }, function (error) {
          if (payload._status === Pending || payload._status === Uninitialized) {
            // Transition to the next state.
            var rejected = payload;
            rejected._status = Rejected;
            rejected._result = error;
          }
        });
        if (payload._status === Uninitialized) {
          // In case, we're still uninitialized, then we're waiting for the thenable
          // to resolve. Set it as pending in the meantime.
          var pending = payload;
          pending._status = Pending;
          pending._result = thenable;
        }
      }
      if (payload._status === Resolved) {
        var moduleObject = payload._result;
        {
          if (moduleObject === undefined) {
            error('lazy: Expected the result of a dynamic imp' + 'ort() call. ' + 'Instead received: %s\n\nYour code should look like: \n  ' +
            // Break up imports to avoid accidentally parsing them as dependencies.
            'const MyComponent = lazy(() => imp' + "ort('./MyComponent'))\n\n" + 'Did you accidentally put curly braces around the import?', moduleObject);
          }
        }
        {
          if (!('default' in moduleObject)) {
            error('lazy: Expected the result of a dynamic imp' + 'ort() call. ' + 'Instead received: %s\n\nYour code should look like: \n  ' +
            // Break up imports to avoid accidentally parsing them as dependencies.
            'const MyComponent = lazy(() => imp' + "ort('./MyComponent'))", moduleObject);
          }
        }
        return moduleObject.default;
      } else {
        throw payload._result;
      }
    }
    function lazy(ctor) {
      var payload = {
        // We use these fields to store the result.
        _status: Uninitialized,
        _result: ctor
      };
      var lazyType = {
        $$typeof: REACT_LAZY_TYPE,
        _payload: payload,
        _init: lazyInitializer
      };
      {
        // In production, this would just set it on the object.
        var defaultProps;
        var propTypes; // $FlowFixMe

        Object.defineProperties(lazyType, {
          defaultProps: {
            configurable: true,
            get: function () {
              return defaultProps;
            },
            set: function (newDefaultProps) {
              error('React.lazy(...): It is not supported to assign `defaultProps` to ' + 'a lazy component import. Either specify them where the component ' + 'is defined, or create a wrapping component around it.');
              defaultProps = newDefaultProps; // Match production behavior more closely:
              // $FlowFixMe

              Object.defineProperty(lazyType, 'defaultProps', {
                enumerable: true
              });
            }
          },
          propTypes: {
            configurable: true,
            get: function () {
              return propTypes;
            },
            set: function (newPropTypes) {
              error('React.lazy(...): It is not supported to assign `propTypes` to ' + 'a lazy component import. Either specify them where the component ' + 'is defined, or create a wrapping component around it.');
              propTypes = newPropTypes; // Match production behavior more closely:
              // $FlowFixMe

              Object.defineProperty(lazyType, 'propTypes', {
                enumerable: true
              });
            }
          }
        });
      }
      return lazyType;
    }
    function forwardRef(render) {
      {
        if (render != null && render.$$typeof === REACT_MEMO_TYPE) {
          error('forwardRef requires a render function but received a `memo` ' + 'component. Instead of forwardRef(memo(...)), use ' + 'memo(forwardRef(...)).');
        } else if (typeof render !== 'function') {
          error('forwardRef requires a render function but was given %s.', render === null ? 'null' : typeof render);
        } else {
          if (render.length !== 0 && render.length !== 2) {
            error('forwardRef render functions accept exactly two parameters: props and ref. %s', render.length === 1 ? 'Did you forget to use the ref parameter?' : 'Any additional parameter will be undefined.');
          }
        }
        if (render != null) {
          if (render.defaultProps != null || render.propTypes != null) {
            error('forwardRef render functions do not support propTypes or defaultProps. ' + 'Did you accidentally pass a React component?');
          }
        }
      }
      var elementType = {
        $$typeof: REACT_FORWARD_REF_TYPE,
        render: render
      };
      {
        var ownName;
        Object.defineProperty(elementType, 'displayName', {
          enumerable: false,
          configurable: true,
          get: function () {
            return ownName;
          },
          set: function (name) {
            ownName = name; // The inner component shouldn't inherit this display name in most cases,
            // because the component may be used elsewhere.
            // But it's nice for anonymous functions to inherit the name,
            // so that our component-stack generation logic will display their frames.
            // An anonymous function generally suggests a pattern like:
            //   React.forwardRef((props, ref) => {...});
            // This kind of inner function is not used elsewhere so the side effect is okay.

            if (!render.name && !render.displayName) {
              render.displayName = name;
            }
          }
        });
      }
      return elementType;
    }
    var REACT_MODULE_REFERENCE;
    {
      REACT_MODULE_REFERENCE = Symbol.for('react.module.reference');
    }
    function isValidElementType(type) {
      if (typeof type === 'string' || typeof type === 'function') {
        return true;
      } // Note: typeof might be other than 'symbol' or 'number' (e.g. if it's a polyfill).

      if (type === REACT_FRAGMENT_TYPE || type === REACT_PROFILER_TYPE || enableDebugTracing || type === REACT_STRICT_MODE_TYPE || type === REACT_SUSPENSE_TYPE || type === REACT_SUSPENSE_LIST_TYPE || enableLegacyHidden || type === REACT_OFFSCREEN_TYPE || enableScopeAPI || enableCacheElement || enableTransitionTracing) {
        return true;
      }
      if (typeof type === 'object' && type !== null) {
        if (type.$$typeof === REACT_LAZY_TYPE || type.$$typeof === REACT_MEMO_TYPE || type.$$typeof === REACT_PROVIDER_TYPE || type.$$typeof === REACT_CONTEXT_TYPE || type.$$typeof === REACT_FORWARD_REF_TYPE ||
        // This needs to include all possible module reference object
        // types supported by any Flight configuration anywhere since
        // we don't know which Flight build this will end up being used
        // with.
        type.$$typeof === REACT_MODULE_REFERENCE || type.getModuleId !== undefined) {
          return true;
        }
      }
      return false;
    }
    function memo(type, compare) {
      {
        if (!isValidElementType(type)) {
          error('memo: The first argument must be a component. Instead ' + 'received: %s', type === null ? 'null' : typeof type);
        }
      }
      var elementType = {
        $$typeof: REACT_MEMO_TYPE,
        type: type,
        compare: compare === undefined ? null : compare
      };
      {
        var ownName;
        Object.defineProperty(elementType, 'displayName', {
          enumerable: false,
          configurable: true,
          get: function () {
            return ownName;
          },
          set: function (name) {
            ownName = name; // The inner component shouldn't inherit this display name in most cases,
            // because the component may be used elsewhere.
            // But it's nice for anonymous functions to inherit the name,
            // so that our component-stack generation logic will display their frames.
            // An anonymous function generally suggests a pattern like:
            //   React.memo((props) => {...});
            // This kind of inner function is not used elsewhere so the side effect is okay.

            if (!type.name && !type.displayName) {
              type.displayName = name;
            }
          }
        });
      }
      return elementType;
    }
    function resolveDispatcher() {
      var dispatcher = ReactCurrentDispatcher.current;
      {
        if (dispatcher === null) {
          error('Invalid hook call. Hooks can only be called inside of the body of a function component. This could happen for' + ' one of the following reasons:\n' + '1. You might have mismatching versions of React and the renderer (such as React DOM)\n' + '2. You might be breaking the Rules of Hooks\n' + '3. You might have more than one copy of React in the same app\n' + 'See https://reactjs.org/link/invalid-hook-call for tips about how to debug and fix this problem.');
        }
      } // Will result in a null access error if accessed outside render phase. We
      // intentionally don't throw our own error because this is in a hot path.
      // Also helps ensure this is inlined.

      return dispatcher;
    }
    function useContext(Context) {
      var dispatcher = resolveDispatcher();
      {
        // TODO: add a more generic warning for invalid values.
        if (Context._context !== undefined) {
          var realContext = Context._context; // Don't deduplicate because this legitimately causes bugs
          // and nobody should be using this in existing code.

          if (realContext.Consumer === Context) {
            error('Calling useContext(Context.Consumer) is not supported, may cause bugs, and will be ' + 'removed in a future major release. Did you mean to call useContext(Context) instead?');
          } else if (realContext.Provider === Context) {
            error('Calling useContext(Context.Provider) is not supported. ' + 'Did you mean to call useContext(Context) instead?');
          }
        }
      }
      return dispatcher.useContext(Context);
    }
    function useState(initialState) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useState(initialState);
    }
    function useReducer(reducer, initialArg, init) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useReducer(reducer, initialArg, init);
    }
    function useRef(initialValue) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useRef(initialValue);
    }
    function useEffect(create, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useEffect(create, deps);
    }
    function useInsertionEffect(create, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useInsertionEffect(create, deps);
    }
    function useLayoutEffect(create, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useLayoutEffect(create, deps);
    }
    function useCallback(callback, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useCallback(callback, deps);
    }
    function useMemo(create, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useMemo(create, deps);
    }
    function useImperativeHandle(ref, create, deps) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useImperativeHandle(ref, create, deps);
    }
    function useDebugValue(value, formatterFn) {
      {
        var dispatcher = resolveDispatcher();
        return dispatcher.useDebugValue(value, formatterFn);
      }
    }
    function useTransition() {
      var dispatcher = resolveDispatcher();
      return dispatcher.useTransition();
    }
    function useDeferredValue(value) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useDeferredValue(value);
    }
    function useId() {
      var dispatcher = resolveDispatcher();
      return dispatcher.useId();
    }
    function useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot) {
      var dispatcher = resolveDispatcher();
      return dispatcher.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
    }

    // Helpers to patch console.logs to avoid logging during side-effect free
    // replaying on render function. This currently only patches the object
    // lazily which won't cover if the log function was extracted eagerly.
    // We could also eagerly patch the method.
    var disabledDepth = 0;
    var prevLog;
    var prevInfo;
    var prevWarn;
    var prevError;
    var prevGroup;
    var prevGroupCollapsed;
    var prevGroupEnd;
    function disabledLog() {}
    disabledLog.__reactDisabledLog = true;
    function disableLogs() {
      {
        if (disabledDepth === 0) {
          /* eslint-disable react-internal/no-production-logging */
          prevLog = console.log;
          prevInfo = console.info;
          prevWarn = console.warn;
          prevError = console.error;
          prevGroup = console.group;
          prevGroupCollapsed = console.groupCollapsed;
          prevGroupEnd = console.groupEnd; // https://github.com/facebook/react/issues/19099

          var props = {
            configurable: true,
            enumerable: true,
            value: disabledLog,
            writable: true
          }; // $FlowFixMe Flow thinks console is immutable.

          Object.defineProperties(console, {
            info: props,
            log: props,
            warn: props,
            error: props,
            group: props,
            groupCollapsed: props,
            groupEnd: props
          });
          /* eslint-enable react-internal/no-production-logging */
        }

        disabledDepth++;
      }
    }
    function reenableLogs() {
      {
        disabledDepth--;
        if (disabledDepth === 0) {
          /* eslint-disable react-internal/no-production-logging */
          var props = {
            configurable: true,
            enumerable: true,
            writable: true
          }; // $FlowFixMe Flow thinks console is immutable.

          Object.defineProperties(console, {
            log: assign({}, props, {
              value: prevLog
            }),
            info: assign({}, props, {
              value: prevInfo
            }),
            warn: assign({}, props, {
              value: prevWarn
            }),
            error: assign({}, props, {
              value: prevError
            }),
            group: assign({}, props, {
              value: prevGroup
            }),
            groupCollapsed: assign({}, props, {
              value: prevGroupCollapsed
            }),
            groupEnd: assign({}, props, {
              value: prevGroupEnd
            })
          });
          /* eslint-enable react-internal/no-production-logging */
        }

        if (disabledDepth < 0) {
          error('disabledDepth fell below zero. ' + 'This is a bug in React. Please file an issue.');
        }
      }
    }
    var ReactCurrentDispatcher$1 = ReactSharedInternals.ReactCurrentDispatcher;
    var prefix;
    function describeBuiltInComponentFrame(name, source, ownerFn) {
      {
        if (prefix === undefined) {
          // Extract the VM specific prefix used by each line.
          try {
            throw Error();
          } catch (x) {
            var match = x.stack.trim().match(/\n( *(at )?)/);
            prefix = match && match[1] || '';
          }
        } // We use the prefix to ensure our stacks line up with native stack frames.

        return '\n' + prefix + name;
      }
    }
    var reentry = false;
    var componentFrameCache;
    {
      var PossiblyWeakMap = typeof WeakMap === 'function' ? WeakMap : Map;
      componentFrameCache = new PossiblyWeakMap();
    }
    function describeNativeComponentFrame(fn, construct) {
      // If something asked for a stack inside a fake render, it should get ignored.
      if (!fn || reentry) {
        return '';
      }
      {
        var frame = componentFrameCache.get(fn);
        if (frame !== undefined) {
          return frame;
        }
      }
      var control;
      reentry = true;
      var previousPrepareStackTrace = Error.prepareStackTrace; // $FlowFixMe It does accept undefined.

      Error.prepareStackTrace = undefined;
      var previousDispatcher;
      {
        previousDispatcher = ReactCurrentDispatcher$1.current; // Set the dispatcher in DEV because this might be call in the render function
        // for warnings.

        ReactCurrentDispatcher$1.current = null;
        disableLogs();
      }
      try {
        // This should throw.
        if (construct) {
          // Something should be setting the props in the constructor.
          var Fake = function () {
            throw Error();
          }; // $FlowFixMe

          Object.defineProperty(Fake.prototype, 'props', {
            set: function () {
              // We use a throwing setter instead of frozen or non-writable props
              // because that won't throw in a non-strict mode function.
              throw Error();
            }
          });
          if (typeof Reflect === 'object' && Reflect.construct) {
            // We construct a different control for this case to include any extra
            // frames added by the construct call.
            try {
              Reflect.construct(Fake, []);
            } catch (x) {
              control = x;
            }
            Reflect.construct(fn, [], Fake);
          } else {
            try {
              Fake.call();
            } catch (x) {
              control = x;
            }
            fn.call(Fake.prototype);
          }
        } else {
          try {
            throw Error();
          } catch (x) {
            control = x;
          }
          fn();
        }
      } catch (sample) {
        // This is inlined manually because closure doesn't do it for us.
        if (sample && control && typeof sample.stack === 'string') {
          // This extracts the first frame from the sample that isn't also in the control.
          // Skipping one frame that we assume is the frame that calls the two.
          var sampleLines = sample.stack.split('\n');
          var controlLines = control.stack.split('\n');
          var s = sampleLines.length - 1;
          var c = controlLines.length - 1;
          while (s >= 1 && c >= 0 && sampleLines[s] !== controlLines[c]) {
            // We expect at least one stack frame to be shared.
            // Typically this will be the root most one. However, stack frames may be
            // cut off due to maximum stack limits. In this case, one maybe cut off
            // earlier than the other. We assume that the sample is longer or the same
            // and there for cut off earlier. So we should find the root most frame in
            // the sample somewhere in the control.
            c--;
          }
          for (; s >= 1 && c >= 0; s--, c--) {
            // Next we find the first one that isn't the same which should be the
            // frame that called our sample function and the control.
            if (sampleLines[s] !== controlLines[c]) {
              // In V8, the first line is describing the message but other VMs don't.
              // If we're about to return the first line, and the control is also on the same
              // line, that's a pretty good indicator that our sample threw at same line as
              // the control. I.e. before we entered the sample frame. So we ignore this result.
              // This can happen if you passed a class to function component, or non-function.
              if (s !== 1 || c !== 1) {
                do {
                  s--;
                  c--; // We may still have similar intermediate frames from the construct call.
                  // The next one that isn't the same should be our match though.

                  if (c < 0 || sampleLines[s] !== controlLines[c]) {
                    // V8 adds a "new" prefix for native classes. Let's remove it to make it prettier.
                    var _frame = '\n' + sampleLines[s].replace(' at new ', ' at '); // If our component frame is labeled "<anonymous>"
                    // but we have a user-provided "displayName"
                    // splice it in to make the stack more readable.

                    if (fn.displayName && _frame.includes('<anonymous>')) {
                      _frame = _frame.replace('<anonymous>', fn.displayName);
                    }
                    {
                      if (typeof fn === 'function') {
                        componentFrameCache.set(fn, _frame);
                      }
                    } // Return the line we found.

                    return _frame;
                  }
                } while (s >= 1 && c >= 0);
              }
              break;
            }
          }
        }
      } finally {
        reentry = false;
        {
          ReactCurrentDispatcher$1.current = previousDispatcher;
          reenableLogs();
        }
        Error.prepareStackTrace = previousPrepareStackTrace;
      } // Fallback to just using the name if we couldn't make it throw.

      var name = fn ? fn.displayName || fn.name : '';
      var syntheticFrame = name ? describeBuiltInComponentFrame(name) : '';
      {
        if (typeof fn === 'function') {
          componentFrameCache.set(fn, syntheticFrame);
        }
      }
      return syntheticFrame;
    }
    function describeFunctionComponentFrame(fn, source, ownerFn) {
      {
        return describeNativeComponentFrame(fn, false);
      }
    }
    function shouldConstruct(Component) {
      var prototype = Component.prototype;
      return !!(prototype && prototype.isReactComponent);
    }
    function describeUnknownElementTypeFrameInDEV(type, source, ownerFn) {
      if (type == null) {
        return '';
      }
      if (typeof type === 'function') {
        {
          return describeNativeComponentFrame(type, shouldConstruct(type));
        }
      }
      if (typeof type === 'string') {
        return describeBuiltInComponentFrame(type);
      }
      switch (type) {
        case REACT_SUSPENSE_TYPE:
          return describeBuiltInComponentFrame('Suspense');
        case REACT_SUSPENSE_LIST_TYPE:
          return describeBuiltInComponentFrame('SuspenseList');
      }
      if (typeof type === 'object') {
        switch (type.$$typeof) {
          case REACT_FORWARD_REF_TYPE:
            return describeFunctionComponentFrame(type.render);
          case REACT_MEMO_TYPE:
            // Memo may contain any component type so we recursively resolve it.
            return describeUnknownElementTypeFrameInDEV(type.type, source, ownerFn);
          case REACT_LAZY_TYPE:
            {
              var lazyComponent = type;
              var payload = lazyComponent._payload;
              var init = lazyComponent._init;
              try {
                // Lazy may contain any component type so we recursively resolve it.
                return describeUnknownElementTypeFrameInDEV(init(payload), source, ownerFn);
              } catch (x) {}
            }
        }
      }
      return '';
    }
    var loggedTypeFailures = {};
    var ReactDebugCurrentFrame$1 = ReactSharedInternals.ReactDebugCurrentFrame;
    function setCurrentlyValidatingElement(element) {
      {
        if (element) {
          var owner = element._owner;
          var stack = describeUnknownElementTypeFrameInDEV(element.type, element._source, owner ? owner.type : null);
          ReactDebugCurrentFrame$1.setExtraStackFrame(stack);
        } else {
          ReactDebugCurrentFrame$1.setExtraStackFrame(null);
        }
      }
    }
    function checkPropTypes(typeSpecs, values, location, componentName, element) {
      {
        // $FlowFixMe This is okay but Flow doesn't know it.
        var has = Function.call.bind(hasOwnProperty);
        for (var typeSpecName in typeSpecs) {
          if (has(typeSpecs, typeSpecName)) {
            var error$1 = void 0; // Prop type validation may throw. In case they do, we don't want to
            // fail the render phase where it didn't fail before. So we log it.
            // After these have been cleaned up, we'll let them throw.

            try {
              // This is intentionally an invariant that gets caught. It's the same
              // behavior as without this statement except with a better message.
              if (typeof typeSpecs[typeSpecName] !== 'function') {
                // eslint-disable-next-line react-internal/prod-error-codes
                var err = Error((componentName || 'React class') + ': ' + location + ' type `' + typeSpecName + '` is invalid; ' + 'it must be a function, usually from the `prop-types` package, but received `' + typeof typeSpecs[typeSpecName] + '`.' + 'This often happens because of typos such as `PropTypes.function` instead of `PropTypes.func`.');
                err.name = 'Invariant Violation';
                throw err;
              }
              error$1 = typeSpecs[typeSpecName](values, typeSpecName, componentName, location, null, 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED');
            } catch (ex) {
              error$1 = ex;
            }
            if (error$1 && !(error$1 instanceof Error)) {
              setCurrentlyValidatingElement(element);
              error('%s: type specification of %s' + ' `%s` is invalid; the type checker ' + 'function must return `null` or an `Error` but returned a %s. ' + 'You may have forgotten to pass an argument to the type checker ' + 'creator (arrayOf, instanceOf, objectOf, oneOf, oneOfType, and ' + 'shape all require an argument).', componentName || 'React class', location, typeSpecName, typeof error$1);
              setCurrentlyValidatingElement(null);
            }
            if (error$1 instanceof Error && !(error$1.message in loggedTypeFailures)) {
              // Only monitor this failure once because there tends to be a lot of the
              // same error.
              loggedTypeFailures[error$1.message] = true;
              setCurrentlyValidatingElement(element);
              error('Failed %s type: %s', location, error$1.message);
              setCurrentlyValidatingElement(null);
            }
          }
        }
      }
    }
    function setCurrentlyValidatingElement$1(element) {
      {
        if (element) {
          var owner = element._owner;
          var stack = describeUnknownElementTypeFrameInDEV(element.type, element._source, owner ? owner.type : null);
          setExtraStackFrame(stack);
        } else {
          setExtraStackFrame(null);
        }
      }
    }
    var propTypesMisspellWarningShown;
    {
      propTypesMisspellWarningShown = false;
    }
    function getDeclarationErrorAddendum() {
      if (ReactCurrentOwner.current) {
        var name = getComponentNameFromType(ReactCurrentOwner.current.type);
        if (name) {
          return '\n\nCheck the render method of `' + name + '`.';
        }
      }
      return '';
    }
    function getSourceInfoErrorAddendum(source) {
      if (source !== undefined) {
        var fileName = source.fileName.replace(/^.*[\\\/]/, '');
        var lineNumber = source.lineNumber;
        return '\n\nCheck your code at ' + fileName + ':' + lineNumber + '.';
      }
      return '';
    }
    function getSourceInfoErrorAddendumForProps(elementProps) {
      if (elementProps !== null && elementProps !== undefined) {
        return getSourceInfoErrorAddendum(elementProps.__source);
      }
      return '';
    }
    /**
     * Warn if there's no key explicitly set on dynamic arrays of children or
     * object keys are not valid. This allows us to keep track of children between
     * updates.
     */

    var ownerHasKeyUseWarning = {};
    function getCurrentComponentErrorInfo(parentType) {
      var info = getDeclarationErrorAddendum();
      if (!info) {
        var parentName = typeof parentType === 'string' ? parentType : parentType.displayName || parentType.name;
        if (parentName) {
          info = "\n\nCheck the top-level render call using <" + parentName + ">.";
        }
      }
      return info;
    }
    /**
     * Warn if the element doesn't have an explicit key assigned to it.
     * This element is in an array. The array could grow and shrink or be
     * reordered. All children that haven't already been validated are required to
     * have a "key" property assigned to it. Error statuses are cached so a warning
     * will only be shown once.
     *
     * @internal
     * @param {ReactElement} element Element that requires a key.
     * @param {*} parentType element's parent's type.
     */

    function validateExplicitKey(element, parentType) {
      if (!element._store || element._store.validated || element.key != null) {
        return;
      }
      element._store.validated = true;
      var currentComponentErrorInfo = getCurrentComponentErrorInfo(parentType);
      if (ownerHasKeyUseWarning[currentComponentErrorInfo]) {
        return;
      }
      ownerHasKeyUseWarning[currentComponentErrorInfo] = true; // Usually the current owner is the offender, but if it accepts children as a
      // property, it may be the creator of the child that's responsible for
      // assigning it a key.

      var childOwner = '';
      if (element && element._owner && element._owner !== ReactCurrentOwner.current) {
        // Give the component that originally created this child.
        childOwner = " It was passed a child from " + getComponentNameFromType(element._owner.type) + ".";
      }
      {
        setCurrentlyValidatingElement$1(element);
        error('Each child in a list should have a unique "key" prop.' + '%s%s See https://reactjs.org/link/warning-keys for more information.', currentComponentErrorInfo, childOwner);
        setCurrentlyValidatingElement$1(null);
      }
    }
    /**
     * Ensure that every element either is passed in a static location, in an
     * array with an explicit keys property defined, or in an object literal
     * with valid key property.
     *
     * @internal
     * @param {ReactNode} node Statically passed child of any type.
     * @param {*} parentType node's parent's type.
     */

    function validateChildKeys(node, parentType) {
      if (typeof node !== 'object') {
        return;
      }
      if (isArray(node)) {
        for (var i = 0; i < node.length; i++) {
          var child = node[i];
          if (isValidElement(child)) {
            validateExplicitKey(child, parentType);
          }
        }
      } else if (isValidElement(node)) {
        // This element was passed in a valid location.
        if (node._store) {
          node._store.validated = true;
        }
      } else if (node) {
        var iteratorFn = getIteratorFn(node);
        if (typeof iteratorFn === 'function') {
          // Entry iterators used to provide implicit keys,
          // but now we print a separate warning for them later.
          if (iteratorFn !== node.entries) {
            var iterator = iteratorFn.call(node);
            var step;
            while (!(step = iterator.next()).done) {
              if (isValidElement(step.value)) {
                validateExplicitKey(step.value, parentType);
              }
            }
          }
        }
      }
    }
    /**
     * Given an element, validate that its props follow the propTypes definition,
     * provided by the type.
     *
     * @param {ReactElement} element
     */

    function validatePropTypes(element) {
      {
        var type = element.type;
        if (type === null || type === undefined || typeof type === 'string') {
          return;
        }
        var propTypes;
        if (typeof type === 'function') {
          propTypes = type.propTypes;
        } else if (typeof type === 'object' && (type.$$typeof === REACT_FORWARD_REF_TYPE ||
        // Note: Memo only checks outer props here.
        // Inner props are checked in the reconciler.
        type.$$typeof === REACT_MEMO_TYPE)) {
          propTypes = type.propTypes;
        } else {
          return;
        }
        if (propTypes) {
          // Intentionally inside to avoid triggering lazy initializers:
          var name = getComponentNameFromType(type);
          checkPropTypes(propTypes, element.props, 'prop', name, element);
        } else if (type.PropTypes !== undefined && !propTypesMisspellWarningShown) {
          propTypesMisspellWarningShown = true; // Intentionally inside to avoid triggering lazy initializers:

          var _name = getComponentNameFromType(type);
          error('Component %s declared `PropTypes` instead of `propTypes`. Did you misspell the property assignment?', _name || 'Unknown');
        }
        if (typeof type.getDefaultProps === 'function' && !type.getDefaultProps.isReactClassApproved) {
          error('getDefaultProps is only used on classic React.createClass ' + 'definitions. Use a static property named `defaultProps` instead.');
        }
      }
    }
    /**
     * Given a fragment, validate that it can only be provided with fragment props
     * @param {ReactElement} fragment
     */

    function validateFragmentProps(fragment) {
      {
        var keys = Object.keys(fragment.props);
        for (var i = 0; i < keys.length; i++) {
          var key = keys[i];
          if (key !== 'children' && key !== 'key') {
            setCurrentlyValidatingElement$1(fragment);
            error('Invalid prop `%s` supplied to `React.Fragment`. ' + 'React.Fragment can only have `key` and `children` props.', key);
            setCurrentlyValidatingElement$1(null);
            break;
          }
        }
        if (fragment.ref !== null) {
          setCurrentlyValidatingElement$1(fragment);
          error('Invalid attribute `ref` supplied to `React.Fragment`.');
          setCurrentlyValidatingElement$1(null);
        }
      }
    }
    function createElementWithValidation(type, props, children) {
      var validType = isValidElementType(type); // We warn in this case but don't throw. We expect the element creation to
      // succeed and there will likely be errors in render.

      if (!validType) {
        var info = '';
        if (type === undefined || typeof type === 'object' && type !== null && Object.keys(type).length === 0) {
          info += ' You likely forgot to export your component from the file ' + "it's defined in, or you might have mixed up default and named imports.";
        }
        var sourceInfo = getSourceInfoErrorAddendumForProps(props);
        if (sourceInfo) {
          info += sourceInfo;
        } else {
          info += getDeclarationErrorAddendum();
        }
        var typeString;
        if (type === null) {
          typeString = 'null';
        } else if (isArray(type)) {
          typeString = 'array';
        } else if (type !== undefined && type.$$typeof === REACT_ELEMENT_TYPE) {
          typeString = "<" + (getComponentNameFromType(type.type) || 'Unknown') + " />";
          info = ' Did you accidentally export a JSX literal instead of a component?';
        } else {
          typeString = typeof type;
        }
        {
          error('React.createElement: type is invalid -- expected a string (for ' + 'built-in components) or a class/function (for composite ' + 'components) but got: %s.%s', typeString, info);
        }
      }
      var element = createElement.apply(this, arguments); // The result can be nullish if a mock or a custom function is used.
      // TODO: Drop this when these are no longer allowed as the type argument.

      if (element == null) {
        return element;
      } // Skip key warning if the type isn't valid since our key validation logic
      // doesn't expect a non-string/function type and can throw confusing errors.
      // We don't want exception behavior to differ between dev and prod.
      // (Rendering will throw with a helpful message and as soon as the type is
      // fixed, the key warnings will appear.)

      if (validType) {
        for (var i = 2; i < arguments.length; i++) {
          validateChildKeys(arguments[i], type);
        }
      }
      if (type === REACT_FRAGMENT_TYPE) {
        validateFragmentProps(element);
      } else {
        validatePropTypes(element);
      }
      return element;
    }
    var didWarnAboutDeprecatedCreateFactory = false;
    function createFactoryWithValidation(type) {
      var validatedFactory = createElementWithValidation.bind(null, type);
      validatedFactory.type = type;
      {
        if (!didWarnAboutDeprecatedCreateFactory) {
          didWarnAboutDeprecatedCreateFactory = true;
          warn('React.createFactory() is deprecated and will be removed in ' + 'a future major release. Consider using JSX ' + 'or use React.createElement() directly instead.');
        } // Legacy hook: remove it

        Object.defineProperty(validatedFactory, 'type', {
          enumerable: false,
          get: function () {
            warn('Factory.type is deprecated. Access the class directly ' + 'before passing it to createFactory.');
            Object.defineProperty(this, 'type', {
              value: type
            });
            return type;
          }
        });
      }
      return validatedFactory;
    }
    function cloneElementWithValidation(element, props, children) {
      var newElement = cloneElement.apply(this, arguments);
      for (var i = 2; i < arguments.length; i++) {
        validateChildKeys(arguments[i], newElement.type);
      }
      validatePropTypes(newElement);
      return newElement;
    }
    function startTransition(scope, options) {
      var prevTransition = ReactCurrentBatchConfig.transition;
      ReactCurrentBatchConfig.transition = {};
      var currentTransition = ReactCurrentBatchConfig.transition;
      {
        ReactCurrentBatchConfig.transition._updatedFibers = new Set();
      }
      try {
        scope();
      } finally {
        ReactCurrentBatchConfig.transition = prevTransition;
        {
          if (prevTransition === null && currentTransition._updatedFibers) {
            var updatedFibersCount = currentTransition._updatedFibers.size;
            if (updatedFibersCount > 10) {
              warn('Detected a large number of updates inside startTransition. ' + 'If this is due to a subscription please re-write it to use React provided hooks. ' + 'Otherwise concurrent mode guarantees are off the table.');
            }
            currentTransition._updatedFibers.clear();
          }
        }
      }
    }
    var didWarnAboutMessageChannel = false;
    var enqueueTaskImpl = null;
    function enqueueTask(task) {
      if (enqueueTaskImpl === null) {
        try {
          // read require off the module object to get around the bundlers.
          // we don't want them to detect a require and bundle a Node polyfill.
          var requireString = ('require' + Math.random()).slice(0, 7);
          var nodeRequire = module && module[requireString]; // assuming we're in node, let's try to get node's
          // version of setImmediate, bypassing fake timers if any.

          enqueueTaskImpl = nodeRequire.call(module, 'timers').setImmediate;
        } catch (_err) {
          // we're in a browser
          // we can't use regular timers because they may still be faked
          // so we try MessageChannel+postMessage instead
          enqueueTaskImpl = function (callback) {
            {
              if (didWarnAboutMessageChannel === false) {
                didWarnAboutMessageChannel = true;
                if (typeof MessageChannel === 'undefined') {
                  error('This browser does not have a MessageChannel implementation, ' + 'so enqueuing tasks via await act(async () => ...) will fail. ' + 'Please file an issue at https://github.com/facebook/react/issues ' + 'if you encounter this warning.');
                }
              }
            }
            var channel = new MessageChannel();
            channel.port1.onmessage = callback;
            channel.port2.postMessage(undefined);
          };
        }
      }
      return enqueueTaskImpl(task);
    }
    var actScopeDepth = 0;
    var didWarnNoAwaitAct = false;
    function act(callback) {
      {
        // `act` calls can be nested, so we track the depth. This represents the
        // number of `act` scopes on the stack.
        var prevActScopeDepth = actScopeDepth;
        actScopeDepth++;
        if (ReactCurrentActQueue.current === null) {
          // This is the outermost `act` scope. Initialize the queue. The reconciler
          // will detect the queue and use it instead of Scheduler.
          ReactCurrentActQueue.current = [];
        }
        var prevIsBatchingLegacy = ReactCurrentActQueue.isBatchingLegacy;
        var result;
        try {
          // Used to reproduce behavior of `batchedUpdates` in legacy mode. Only
          // set to `true` while the given callback is executed, not for updates
          // triggered during an async event, because this is how the legacy
          // implementation of `act` behaved.
          ReactCurrentActQueue.isBatchingLegacy = true;
          result = callback(); // Replicate behavior of original `act` implementation in legacy mode,
          // which flushed updates immediately after the scope function exits, even
          // if it's an async function.

          if (!prevIsBatchingLegacy && ReactCurrentActQueue.didScheduleLegacyUpdate) {
            var queue = ReactCurrentActQueue.current;
            if (queue !== null) {
              ReactCurrentActQueue.didScheduleLegacyUpdate = false;
              flushActQueue(queue);
            }
          }
        } catch (error) {
          popActScope(prevActScopeDepth);
          throw error;
        } finally {
          ReactCurrentActQueue.isBatchingLegacy = prevIsBatchingLegacy;
        }
        if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
          var thenableResult = result; // The callback is an async function (i.e. returned a promise). Wait
          // for it to resolve before exiting the current scope.

          var wasAwaited = false;
          var thenable = {
            then: function (resolve, reject) {
              wasAwaited = true;
              thenableResult.then(function (returnValue) {
                popActScope(prevActScopeDepth);
                if (actScopeDepth === 0) {
                  // We've exited the outermost act scope. Recursively flush the
                  // queue until there's no remaining work.
                  recursivelyFlushAsyncActWork(returnValue, resolve, reject);
                } else {
                  resolve(returnValue);
                }
              }, function (error) {
                // The callback threw an error.
                popActScope(prevActScopeDepth);
                reject(error);
              });
            }
          };
          {
            if (!didWarnNoAwaitAct && typeof Promise !== 'undefined') {
              // eslint-disable-next-line no-undef
              Promise.resolve().then(function () {}).then(function () {
                if (!wasAwaited) {
                  didWarnNoAwaitAct = true;
                  error('You called act(async () => ...) without await. ' + 'This could lead to unexpected testing behaviour, ' + 'interleaving multiple act calls and mixing their ' + 'scopes. ' + 'You should - await act(async () => ...);');
                }
              });
            }
          }
          return thenable;
        } else {
          var returnValue = result; // The callback is not an async function. Exit the current scope
          // immediately, without awaiting.

          popActScope(prevActScopeDepth);
          if (actScopeDepth === 0) {
            // Exiting the outermost act scope. Flush the queue.
            var _queue = ReactCurrentActQueue.current;
            if (_queue !== null) {
              flushActQueue(_queue);
              ReactCurrentActQueue.current = null;
            } // Return a thenable. If the user awaits it, we'll flush again in
            // case additional work was scheduled by a microtask.

            var _thenable = {
              then: function (resolve, reject) {
                // Confirm we haven't re-entered another `act` scope, in case
                // the user does something weird like await the thenable
                // multiple times.
                if (ReactCurrentActQueue.current === null) {
                  // Recursively flush the queue until there's no remaining work.
                  ReactCurrentActQueue.current = [];
                  recursivelyFlushAsyncActWork(returnValue, resolve, reject);
                } else {
                  resolve(returnValue);
                }
              }
            };
            return _thenable;
          } else {
            // Since we're inside a nested `act` scope, the returned thenable
            // immediately resolves. The outer scope will flush the queue.
            var _thenable2 = {
              then: function (resolve, reject) {
                resolve(returnValue);
              }
            };
            return _thenable2;
          }
        }
      }
    }
    function popActScope(prevActScopeDepth) {
      {
        if (prevActScopeDepth !== actScopeDepth - 1) {
          error('You seem to have overlapping act() calls, this is not supported. ' + 'Be sure to await previous act() calls before making a new one. ');
        }
        actScopeDepth = prevActScopeDepth;
      }
    }
    function recursivelyFlushAsyncActWork(returnValue, resolve, reject) {
      {
        var queue = ReactCurrentActQueue.current;
        if (queue !== null) {
          try {
            flushActQueue(queue);
            enqueueTask(function () {
              if (queue.length === 0) {
                // No additional work was scheduled. Finish.
                ReactCurrentActQueue.current = null;
                resolve(returnValue);
              } else {
                // Keep flushing work until there's none left.
                recursivelyFlushAsyncActWork(returnValue, resolve, reject);
              }
            });
          } catch (error) {
            reject(error);
          }
        } else {
          resolve(returnValue);
        }
      }
    }
    var isFlushing = false;
    function flushActQueue(queue) {
      {
        if (!isFlushing) {
          // Prevent re-entrance.
          isFlushing = true;
          var i = 0;
          try {
            for (; i < queue.length; i++) {
              var callback = queue[i];
              do {
                callback = callback(true);
              } while (callback !== null);
            }
            queue.length = 0;
          } catch (error) {
            // If something throws, leave the remaining callbacks on the queue.
            queue = queue.slice(i + 1);
            throw error;
          } finally {
            isFlushing = false;
          }
        }
      }
    }
    var createElement$1 = createElementWithValidation;
    var cloneElement$1 = cloneElementWithValidation;
    var createFactory = createFactoryWithValidation;
    var Children = {
      map: mapChildren,
      forEach: forEachChildren,
      count: countChildren,
      toArray: toArray,
      only: onlyChild
    };
    exports.Children = Children;
    exports.Component = Component;
    exports.Fragment = REACT_FRAGMENT_TYPE;
    exports.Profiler = REACT_PROFILER_TYPE;
    exports.PureComponent = PureComponent;
    exports.StrictMode = REACT_STRICT_MODE_TYPE;
    exports.Suspense = REACT_SUSPENSE_TYPE;
    exports.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = ReactSharedInternals;
    exports.cloneElement = cloneElement$1;
    exports.createContext = createContext;
    exports.createElement = createElement$1;
    exports.createFactory = createFactory;
    exports.createRef = createRef;
    exports.forwardRef = forwardRef;
    exports.isValidElement = isValidElement;
    exports.lazy = lazy;
    exports.memo = memo;
    exports.startTransition = startTransition;
    exports.unstable_act = act;
    exports.useCallback = useCallback;
    exports.useContext = useContext;
    exports.useDebugValue = useDebugValue;
    exports.useDeferredValue = useDeferredValue;
    exports.useEffect = useEffect;
    exports.useId = useId;
    exports.useImperativeHandle = useImperativeHandle;
    exports.useInsertionEffect = useInsertionEffect;
    exports.useLayoutEffect = useLayoutEffect;
    exports.useMemo = useMemo;
    exports.useReducer = useReducer;
    exports.useRef = useRef;
    exports.useState = useState;
    exports.useSyncExternalStore = useSyncExternalStore;
    exports.useTransition = useTransition;
    exports.version = ReactVersion;
    /* global __REACT_DEVTOOLS_GLOBAL_HOOK__ */
    if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' && typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop === 'function') {
      __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(new Error());
    }
  })();
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJfX1JFQUNUX0RFVlRPT0xTX0dMT0JBTF9IT09LX18iLCJyZWdpc3RlckludGVybmFsTW9kdWxlU3RhcnQiLCJFcnJvciIsIlJlYWN0VmVyc2lvbiIsIlJFQUNUX0VMRU1FTlRfVFlQRSIsIlN5bWJvbCIsImZvciIsIlJFQUNUX1BPUlRBTF9UWVBFIiwiUkVBQ1RfRlJBR01FTlRfVFlQRSIsIlJFQUNUX1NUUklDVF9NT0RFX1RZUEUiLCJSRUFDVF9QUk9GSUxFUl9UWVBFIiwiUkVBQ1RfUFJPVklERVJfVFlQRSIsIlJFQUNUX0NPTlRFWFRfVFlQRSIsIlJFQUNUX0ZPUldBUkRfUkVGX1RZUEUiLCJSRUFDVF9TVVNQRU5TRV9UWVBFIiwiUkVBQ1RfU1VTUEVOU0VfTElTVF9UWVBFIiwiUkVBQ1RfTUVNT19UWVBFIiwiUkVBQ1RfTEFaWV9UWVBFIiwiUkVBQ1RfT0ZGU0NSRUVOX1RZUEUiLCJNQVlCRV9JVEVSQVRPUl9TWU1CT0wiLCJpdGVyYXRvciIsIkZBVVhfSVRFUkFUT1JfU1lNQk9MIiwiZ2V0SXRlcmF0b3JGbiIsIm1heWJlSXRlcmFibGUiLCJtYXliZUl0ZXJhdG9yIiwiUmVhY3RDdXJyZW50RGlzcGF0Y2hlciIsImN1cnJlbnQiLCJSZWFjdEN1cnJlbnRCYXRjaENvbmZpZyIsInRyYW5zaXRpb24iLCJSZWFjdEN1cnJlbnRBY3RRdWV1ZSIsImlzQmF0Y2hpbmdMZWdhY3kiLCJkaWRTY2hlZHVsZUxlZ2FjeVVwZGF0ZSIsIlJlYWN0Q3VycmVudE93bmVyIiwiUmVhY3REZWJ1Z0N1cnJlbnRGcmFtZSIsImN1cnJlbnRFeHRyYVN0YWNrRnJhbWUiLCJzZXRFeHRyYVN0YWNrRnJhbWUiLCJzdGFjayIsImdldEN1cnJlbnRTdGFjayIsImdldFN0YWNrQWRkZW5kdW0iLCJpbXBsIiwiZW5hYmxlU2NvcGVBUEkiLCJlbmFibGVDYWNoZUVsZW1lbnQiLCJlbmFibGVUcmFuc2l0aW9uVHJhY2luZyIsImVuYWJsZUxlZ2FjeUhpZGRlbiIsImVuYWJsZURlYnVnVHJhY2luZyIsIlJlYWN0U2hhcmVkSW50ZXJuYWxzIiwid2FybiIsImZvcm1hdCIsIl9sZW4iLCJhcmd1bWVudHMiLCJsZW5ndGgiLCJhcmdzIiwiQXJyYXkiLCJfa2V5IiwicHJpbnRXYXJuaW5nIiwiZXJyb3IiLCJfbGVuMiIsIl9rZXkyIiwibGV2ZWwiLCJjb25jYXQiLCJhcmdzV2l0aEZvcm1hdCIsIm1hcCIsIml0ZW0iLCJTdHJpbmciLCJ1bnNoaWZ0IiwiRnVuY3Rpb24iLCJwcm90b3R5cGUiLCJhcHBseSIsImNhbGwiLCJjb25zb2xlIiwiZGlkV2FyblN0YXRlVXBkYXRlRm9yVW5tb3VudGVkQ29tcG9uZW50Iiwid2Fybk5vb3AiLCJwdWJsaWNJbnN0YW5jZSIsImNhbGxlck5hbWUiLCJfY29uc3RydWN0b3IiLCJjb25zdHJ1Y3RvciIsImNvbXBvbmVudE5hbWUiLCJkaXNwbGF5TmFtZSIsIm5hbWUiLCJ3YXJuaW5nS2V5IiwiUmVhY3ROb29wVXBkYXRlUXVldWUiLCJpc01vdW50ZWQiLCJlbnF1ZXVlRm9yY2VVcGRhdGUiLCJjYWxsYmFjayIsImVucXVldWVSZXBsYWNlU3RhdGUiLCJjb21wbGV0ZVN0YXRlIiwiZW5xdWV1ZVNldFN0YXRlIiwicGFydGlhbFN0YXRlIiwiYXNzaWduIiwiT2JqZWN0IiwiZW1wdHlPYmplY3QiLCJmcmVlemUiLCJDb21wb25lbnQiLCJwcm9wcyIsImNvbnRleHQiLCJ1cGRhdGVyIiwicmVmcyIsImlzUmVhY3RDb21wb25lbnQiLCJzZXRTdGF0ZSIsImZvcmNlVXBkYXRlIiwiZGVwcmVjYXRlZEFQSXMiLCJyZXBsYWNlU3RhdGUiLCJkZWZpbmVEZXByZWNhdGlvbldhcm5pbmciLCJtZXRob2ROYW1lIiwiaW5mbyIsImRlZmluZVByb3BlcnR5IiwiZ2V0IiwidW5kZWZpbmVkIiwiZm5OYW1lIiwiaGFzT3duUHJvcGVydHkiLCJDb21wb25lbnREdW1teSIsIlB1cmVDb21wb25lbnQiLCJwdXJlQ29tcG9uZW50UHJvdG90eXBlIiwiaXNQdXJlUmVhY3RDb21wb25lbnQiLCJjcmVhdGVSZWYiLCJyZWZPYmplY3QiLCJzZWFsIiwiaXNBcnJheUltcGwiLCJpc0FycmF5IiwiYSIsInR5cGVOYW1lIiwidmFsdWUiLCJoYXNUb1N0cmluZ1RhZyIsInRvU3RyaW5nVGFnIiwidHlwZSIsIndpbGxDb2VyY2lvblRocm93IiwidGVzdFN0cmluZ0NvZXJjaW9uIiwiZSIsImNoZWNrS2V5U3RyaW5nQ29lcmNpb24iLCJnZXRXcmFwcGVkTmFtZSIsIm91dGVyVHlwZSIsImlubmVyVHlwZSIsIndyYXBwZXJOYW1lIiwiZnVuY3Rpb25OYW1lIiwiZ2V0Q29udGV4dE5hbWUiLCJnZXRDb21wb25lbnROYW1lRnJvbVR5cGUiLCJ0YWciLCIkJHR5cGVvZiIsInByb3ZpZGVyIiwiX2NvbnRleHQiLCJyZW5kZXIiLCJvdXRlck5hbWUiLCJsYXp5Q29tcG9uZW50IiwicGF5bG9hZCIsIl9wYXlsb2FkIiwiaW5pdCIsIl9pbml0IiwieCIsIlJFU0VSVkVEX1BST1BTIiwia2V5IiwicmVmIiwiX19zZWxmIiwiX19zb3VyY2UiLCJzcGVjaWFsUHJvcEtleVdhcm5pbmdTaG93biIsInNwZWNpYWxQcm9wUmVmV2FybmluZ1Nob3duIiwiZGlkV2FybkFib3V0U3RyaW5nUmVmcyIsImhhc1ZhbGlkUmVmIiwiY29uZmlnIiwiZ2V0dGVyIiwiZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yIiwiaXNSZWFjdFdhcm5pbmciLCJoYXNWYWxpZEtleSIsImRlZmluZUtleVByb3BXYXJuaW5nR2V0dGVyIiwid2FybkFib3V0QWNjZXNzaW5nS2V5IiwiY29uZmlndXJhYmxlIiwiZGVmaW5lUmVmUHJvcFdhcm5pbmdHZXR0ZXIiLCJ3YXJuQWJvdXRBY2Nlc3NpbmdSZWYiLCJ3YXJuSWZTdHJpbmdSZWZDYW5ub3RCZUF1dG9Db252ZXJ0ZWQiLCJzdGF0ZU5vZGUiLCJSZWFjdEVsZW1lbnQiLCJzZWxmIiwic291cmNlIiwib3duZXIiLCJlbGVtZW50IiwiX293bmVyIiwiX3N0b3JlIiwiZW51bWVyYWJsZSIsIndyaXRhYmxlIiwiY3JlYXRlRWxlbWVudCIsImNoaWxkcmVuIiwicHJvcE5hbWUiLCJjaGlsZHJlbkxlbmd0aCIsImNoaWxkQXJyYXkiLCJpIiwiZGVmYXVsdFByb3BzIiwiY2xvbmVBbmRSZXBsYWNlS2V5Iiwib2xkRWxlbWVudCIsIm5ld0tleSIsIm5ld0VsZW1lbnQiLCJfc2VsZiIsIl9zb3VyY2UiLCJjbG9uZUVsZW1lbnQiLCJpc1ZhbGlkRWxlbWVudCIsIm9iamVjdCIsIlNFUEFSQVRPUiIsIlNVQlNFUEFSQVRPUiIsImVzY2FwZSIsImVzY2FwZVJlZ2V4IiwiZXNjYXBlckxvb2t1cCIsImVzY2FwZWRTdHJpbmciLCJyZXBsYWNlIiwibWF0Y2giLCJkaWRXYXJuQWJvdXRNYXBzIiwidXNlclByb3ZpZGVkS2V5RXNjYXBlUmVnZXgiLCJlc2NhcGVVc2VyUHJvdmlkZWRLZXkiLCJ0ZXh0IiwiZ2V0RWxlbWVudEtleSIsImluZGV4IiwidG9TdHJpbmciLCJtYXBJbnRvQXJyYXkiLCJhcnJheSIsImVzY2FwZWRQcmVmaXgiLCJuYW1lU29GYXIiLCJpbnZva2VDYWxsYmFjayIsIl9jaGlsZCIsIm1hcHBlZENoaWxkIiwiY2hpbGRLZXkiLCJlc2NhcGVkQ2hpbGRLZXkiLCJjIiwicHVzaCIsImNoaWxkIiwibmV4dE5hbWUiLCJzdWJ0cmVlQ291bnQiLCJuZXh0TmFtZVByZWZpeCIsIml0ZXJhdG9yRm4iLCJpdGVyYWJsZUNoaWxkcmVuIiwiZW50cmllcyIsInN0ZXAiLCJpaSIsIm5leHQiLCJkb25lIiwiY2hpbGRyZW5TdHJpbmciLCJrZXlzIiwiam9pbiIsIm1hcENoaWxkcmVuIiwiZnVuYyIsInJlc3VsdCIsImNvdW50IiwiY291bnRDaGlsZHJlbiIsIm4iLCJmb3JFYWNoQ2hpbGRyZW4iLCJmb3JFYWNoRnVuYyIsImZvckVhY2hDb250ZXh0IiwidG9BcnJheSIsIm9ubHlDaGlsZCIsImNyZWF0ZUNvbnRleHQiLCJkZWZhdWx0VmFsdWUiLCJfY3VycmVudFZhbHVlIiwiX2N1cnJlbnRWYWx1ZTIiLCJfdGhyZWFkQ291bnQiLCJQcm92aWRlciIsIkNvbnN1bWVyIiwiX2RlZmF1bHRWYWx1ZSIsIl9nbG9iYWxOYW1lIiwiaGFzV2FybmVkQWJvdXRVc2luZ05lc3RlZENvbnRleHRDb25zdW1lcnMiLCJoYXNXYXJuZWRBYm91dFVzaW5nQ29uc3VtZXJQcm92aWRlciIsImhhc1dhcm5lZEFib3V0RGlzcGxheU5hbWVPbkNvbnN1bWVyIiwiZGVmaW5lUHJvcGVydGllcyIsInNldCIsIl9Qcm92aWRlciIsIl9jdXJyZW50UmVuZGVyZXIiLCJfY3VycmVudFJlbmRlcmVyMiIsIlVuaW5pdGlhbGl6ZWQiLCJQZW5kaW5nIiwiUmVzb2x2ZWQiLCJSZWplY3RlZCIsImxhenlJbml0aWFsaXplciIsIl9zdGF0dXMiLCJjdG9yIiwiX3Jlc3VsdCIsInRoZW5hYmxlIiwidGhlbiIsIm1vZHVsZU9iamVjdCIsInJlc29sdmVkIiwicmVqZWN0ZWQiLCJwZW5kaW5nIiwiZGVmYXVsdCIsImxhenkiLCJsYXp5VHlwZSIsInByb3BUeXBlcyIsIm5ld0RlZmF1bHRQcm9wcyIsIm5ld1Byb3BUeXBlcyIsImZvcndhcmRSZWYiLCJlbGVtZW50VHlwZSIsIm93bk5hbWUiLCJSRUFDVF9NT0RVTEVfUkVGRVJFTkNFIiwiaXNWYWxpZEVsZW1lbnRUeXBlIiwiZ2V0TW9kdWxlSWQiLCJtZW1vIiwiY29tcGFyZSIsInJlc29sdmVEaXNwYXRjaGVyIiwiZGlzcGF0Y2hlciIsInVzZUNvbnRleHQiLCJDb250ZXh0IiwicmVhbENvbnRleHQiLCJ1c2VTdGF0ZSIsImluaXRpYWxTdGF0ZSIsInVzZVJlZHVjZXIiLCJyZWR1Y2VyIiwiaW5pdGlhbEFyZyIsInVzZVJlZiIsImluaXRpYWxWYWx1ZSIsInVzZUVmZmVjdCIsImNyZWF0ZSIsImRlcHMiLCJ1c2VJbnNlcnRpb25FZmZlY3QiLCJ1c2VMYXlvdXRFZmZlY3QiLCJ1c2VDYWxsYmFjayIsInVzZU1lbW8iLCJ1c2VJbXBlcmF0aXZlSGFuZGxlIiwidXNlRGVidWdWYWx1ZSIsImZvcm1hdHRlckZuIiwidXNlVHJhbnNpdGlvbiIsInVzZURlZmVycmVkVmFsdWUiLCJ1c2VJZCIsInVzZVN5bmNFeHRlcm5hbFN0b3JlIiwic3Vic2NyaWJlIiwiZ2V0U25hcHNob3QiLCJnZXRTZXJ2ZXJTbmFwc2hvdCIsImRpc2FibGVkRGVwdGgiLCJwcmV2TG9nIiwicHJldkluZm8iLCJwcmV2V2FybiIsInByZXZFcnJvciIsInByZXZHcm91cCIsInByZXZHcm91cENvbGxhcHNlZCIsInByZXZHcm91cEVuZCIsImRpc2FibGVkTG9nIiwiX19yZWFjdERpc2FibGVkTG9nIiwiZGlzYWJsZUxvZ3MiLCJsb2ciLCJncm91cCIsImdyb3VwQ29sbGFwc2VkIiwiZ3JvdXBFbmQiLCJyZWVuYWJsZUxvZ3MiLCJSZWFjdEN1cnJlbnREaXNwYXRjaGVyJDEiLCJwcmVmaXgiLCJkZXNjcmliZUJ1aWx0SW5Db21wb25lbnRGcmFtZSIsIm93bmVyRm4iLCJ0cmltIiwicmVlbnRyeSIsImNvbXBvbmVudEZyYW1lQ2FjaGUiLCJQb3NzaWJseVdlYWtNYXAiLCJXZWFrTWFwIiwiTWFwIiwiZGVzY3JpYmVOYXRpdmVDb21wb25lbnRGcmFtZSIsImZuIiwiY29uc3RydWN0IiwiZnJhbWUiLCJjb250cm9sIiwicHJldmlvdXNQcmVwYXJlU3RhY2tUcmFjZSIsInByZXBhcmVTdGFja1RyYWNlIiwicHJldmlvdXNEaXNwYXRjaGVyIiwiRmFrZSIsIlJlZmxlY3QiLCJzYW1wbGUiLCJzYW1wbGVMaW5lcyIsInNwbGl0IiwiY29udHJvbExpbmVzIiwicyIsIl9mcmFtZSIsImluY2x1ZGVzIiwic3ludGhldGljRnJhbWUiLCJkZXNjcmliZUZ1bmN0aW9uQ29tcG9uZW50RnJhbWUiLCJzaG91bGRDb25zdHJ1Y3QiLCJkZXNjcmliZVVua25vd25FbGVtZW50VHlwZUZyYW1lSW5ERVYiLCJsb2dnZWRUeXBlRmFpbHVyZXMiLCJSZWFjdERlYnVnQ3VycmVudEZyYW1lJDEiLCJzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCIsImNoZWNrUHJvcFR5cGVzIiwidHlwZVNwZWNzIiwidmFsdWVzIiwibG9jYXRpb24iLCJoYXMiLCJiaW5kIiwidHlwZVNwZWNOYW1lIiwiZXJyb3IkMSIsImVyciIsImV4IiwibWVzc2FnZSIsInNldEN1cnJlbnRseVZhbGlkYXRpbmdFbGVtZW50JDEiLCJwcm9wVHlwZXNNaXNzcGVsbFdhcm5pbmdTaG93biIsImdldERlY2xhcmF0aW9uRXJyb3JBZGRlbmR1bSIsImdldFNvdXJjZUluZm9FcnJvckFkZGVuZHVtIiwiZmlsZU5hbWUiLCJsaW5lTnVtYmVyIiwiZ2V0U291cmNlSW5mb0Vycm9yQWRkZW5kdW1Gb3JQcm9wcyIsImVsZW1lbnRQcm9wcyIsIm93bmVySGFzS2V5VXNlV2FybmluZyIsImdldEN1cnJlbnRDb21wb25lbnRFcnJvckluZm8iLCJwYXJlbnRUeXBlIiwicGFyZW50TmFtZSIsInZhbGlkYXRlRXhwbGljaXRLZXkiLCJ2YWxpZGF0ZWQiLCJjdXJyZW50Q29tcG9uZW50RXJyb3JJbmZvIiwiY2hpbGRPd25lciIsInZhbGlkYXRlQ2hpbGRLZXlzIiwibm9kZSIsInZhbGlkYXRlUHJvcFR5cGVzIiwiUHJvcFR5cGVzIiwiX25hbWUiLCJnZXREZWZhdWx0UHJvcHMiLCJpc1JlYWN0Q2xhc3NBcHByb3ZlZCIsInZhbGlkYXRlRnJhZ21lbnRQcm9wcyIsImZyYWdtZW50IiwiY3JlYXRlRWxlbWVudFdpdGhWYWxpZGF0aW9uIiwidmFsaWRUeXBlIiwic291cmNlSW5mbyIsInR5cGVTdHJpbmciLCJkaWRXYXJuQWJvdXREZXByZWNhdGVkQ3JlYXRlRmFjdG9yeSIsImNyZWF0ZUZhY3RvcnlXaXRoVmFsaWRhdGlvbiIsInZhbGlkYXRlZEZhY3RvcnkiLCJjbG9uZUVsZW1lbnRXaXRoVmFsaWRhdGlvbiIsInN0YXJ0VHJhbnNpdGlvbiIsInNjb3BlIiwib3B0aW9ucyIsInByZXZUcmFuc2l0aW9uIiwiY3VycmVudFRyYW5zaXRpb24iLCJfdXBkYXRlZEZpYmVycyIsIlNldCIsInVwZGF0ZWRGaWJlcnNDb3VudCIsInNpemUiLCJjbGVhciIsImRpZFdhcm5BYm91dE1lc3NhZ2VDaGFubmVsIiwiZW5xdWV1ZVRhc2tJbXBsIiwiZW5xdWV1ZVRhc2siLCJ0YXNrIiwicmVxdWlyZVN0cmluZyIsIk1hdGgiLCJyYW5kb20iLCJzbGljZSIsIm5vZGVSZXF1aXJlIiwibW9kdWxlIiwic2V0SW1tZWRpYXRlIiwiX2VyciIsIk1lc3NhZ2VDaGFubmVsIiwiY2hhbm5lbCIsInBvcnQxIiwib25tZXNzYWdlIiwicG9ydDIiLCJwb3N0TWVzc2FnZSIsImFjdFNjb3BlRGVwdGgiLCJkaWRXYXJuTm9Bd2FpdEFjdCIsImFjdCIsInByZXZBY3RTY29wZURlcHRoIiwicHJldklzQmF0Y2hpbmdMZWdhY3kiLCJxdWV1ZSIsImZsdXNoQWN0UXVldWUiLCJwb3BBY3RTY29wZSIsInRoZW5hYmxlUmVzdWx0Iiwid2FzQXdhaXRlZCIsInJlc29sdmUiLCJyZWplY3QiLCJyZXR1cm5WYWx1ZSIsInJlY3Vyc2l2ZWx5Rmx1c2hBc3luY0FjdFdvcmsiLCJQcm9taXNlIiwiX3F1ZXVlIiwiX3RoZW5hYmxlIiwiX3RoZW5hYmxlMiIsImlzRmx1c2hpbmciLCJjcmVhdGVFbGVtZW50JDEiLCJjbG9uZUVsZW1lbnQkMSIsImNyZWF0ZUZhY3RvcnkiLCJDaGlsZHJlbiIsImZvckVhY2giLCJvbmx5IiwiZXhwb3J0cyIsIkZyYWdtZW50IiwiUHJvZmlsZXIiLCJTdHJpY3RNb2RlIiwiU3VzcGVuc2UiLCJfX1NFQ1JFVF9JTlRFUk5BTFNfRE9fTk9UX1VTRV9PUl9ZT1VfV0lMTF9CRV9GSVJFRCIsInVuc3RhYmxlX2FjdCIsInZlcnNpb24iLCJyZWdpc3RlckludGVybmFsTW9kdWxlU3RvcCJdLCJzb3VyY2VzIjpbInJlYWN0LmRldmVsb3BtZW50LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQGxpY2Vuc2UgUmVhY3RcbiAqIHJlYWN0LmRldmVsb3BtZW50LmpzXG4gKlxuICogQ29weXJpZ2h0IChjKSBGYWNlYm9vaywgSW5jLiBhbmQgaXRzIGFmZmlsaWF0ZXMuXG4gKlxuICogVGhpcyBzb3VyY2UgY29kZSBpcyBsaWNlbnNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2UgZm91bmQgaW4gdGhlXG4gKiBMSUNFTlNFIGZpbGUgaW4gdGhlIHJvb3QgZGlyZWN0b3J5IG9mIHRoaXMgc291cmNlIHRyZWUuXG4gKi9cblxuJ3VzZSBzdHJpY3QnO1xuXG5pZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09IFwicHJvZHVjdGlvblwiKSB7XG4gIChmdW5jdGlvbigpIHtcblxuICAgICAgICAgICd1c2Ugc3RyaWN0JztcblxuLyogZ2xvYmFsIF9fUkVBQ1RfREVWVE9PTFNfR0xPQkFMX0hPT0tfXyAqL1xuaWYgKFxuICB0eXBlb2YgX19SRUFDVF9ERVZUT09MU19HTE9CQUxfSE9PS19fICE9PSAndW5kZWZpbmVkJyAmJlxuICB0eXBlb2YgX19SRUFDVF9ERVZUT09MU19HTE9CQUxfSE9PS19fLnJlZ2lzdGVySW50ZXJuYWxNb2R1bGVTdGFydCA9PT1cbiAgICAnZnVuY3Rpb24nXG4pIHtcbiAgX19SRUFDVF9ERVZUT09MU19HTE9CQUxfSE9PS19fLnJlZ2lzdGVySW50ZXJuYWxNb2R1bGVTdGFydChuZXcgRXJyb3IoKSk7XG59XG4gICAgICAgICAgdmFyIFJlYWN0VmVyc2lvbiA9ICcxOC4yLjAnO1xuXG4vLyBBVFRFTlRJT05cbi8vIFdoZW4gYWRkaW5nIG5ldyBzeW1ib2xzIHRvIHRoaXMgZmlsZSxcbi8vIFBsZWFzZSBjb25zaWRlciBhbHNvIGFkZGluZyB0byAncmVhY3QtZGV2dG9vbHMtc2hhcmVkL3NyYy9iYWNrZW5kL1JlYWN0U3ltYm9scydcbi8vIFRoZSBTeW1ib2wgdXNlZCB0byB0YWcgdGhlIFJlYWN0RWxlbWVudC1saWtlIHR5cGVzLlxudmFyIFJFQUNUX0VMRU1FTlRfVFlQRSA9IFN5bWJvbC5mb3IoJ3JlYWN0LmVsZW1lbnQnKTtcbnZhciBSRUFDVF9QT1JUQUxfVFlQRSA9IFN5bWJvbC5mb3IoJ3JlYWN0LnBvcnRhbCcpO1xudmFyIFJFQUNUX0ZSQUdNRU5UX1RZUEUgPSBTeW1ib2wuZm9yKCdyZWFjdC5mcmFnbWVudCcpO1xudmFyIFJFQUNUX1NUUklDVF9NT0RFX1RZUEUgPSBTeW1ib2wuZm9yKCdyZWFjdC5zdHJpY3RfbW9kZScpO1xudmFyIFJFQUNUX1BST0ZJTEVSX1RZUEUgPSBTeW1ib2wuZm9yKCdyZWFjdC5wcm9maWxlcicpO1xudmFyIFJFQUNUX1BST1ZJREVSX1RZUEUgPSBTeW1ib2wuZm9yKCdyZWFjdC5wcm92aWRlcicpO1xudmFyIFJFQUNUX0NPTlRFWFRfVFlQRSA9IFN5bWJvbC5mb3IoJ3JlYWN0LmNvbnRleHQnKTtcbnZhciBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFID0gU3ltYm9sLmZvcigncmVhY3QuZm9yd2FyZF9yZWYnKTtcbnZhciBSRUFDVF9TVVNQRU5TRV9UWVBFID0gU3ltYm9sLmZvcigncmVhY3Quc3VzcGVuc2UnKTtcbnZhciBSRUFDVF9TVVNQRU5TRV9MSVNUX1RZUEUgPSBTeW1ib2wuZm9yKCdyZWFjdC5zdXNwZW5zZV9saXN0Jyk7XG52YXIgUkVBQ1RfTUVNT19UWVBFID0gU3ltYm9sLmZvcigncmVhY3QubWVtbycpO1xudmFyIFJFQUNUX0xBWllfVFlQRSA9IFN5bWJvbC5mb3IoJ3JlYWN0LmxhenknKTtcbnZhciBSRUFDVF9PRkZTQ1JFRU5fVFlQRSA9IFN5bWJvbC5mb3IoJ3JlYWN0Lm9mZnNjcmVlbicpO1xudmFyIE1BWUJFX0lURVJBVE9SX1NZTUJPTCA9IFN5bWJvbC5pdGVyYXRvcjtcbnZhciBGQVVYX0lURVJBVE9SX1NZTUJPTCA9ICdAQGl0ZXJhdG9yJztcbmZ1bmN0aW9uIGdldEl0ZXJhdG9yRm4obWF5YmVJdGVyYWJsZSkge1xuICBpZiAobWF5YmVJdGVyYWJsZSA9PT0gbnVsbCB8fCB0eXBlb2YgbWF5YmVJdGVyYWJsZSAhPT0gJ29iamVjdCcpIHtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHZhciBtYXliZUl0ZXJhdG9yID0gTUFZQkVfSVRFUkFUT1JfU1lNQk9MICYmIG1heWJlSXRlcmFibGVbTUFZQkVfSVRFUkFUT1JfU1lNQk9MXSB8fCBtYXliZUl0ZXJhYmxlW0ZBVVhfSVRFUkFUT1JfU1lNQk9MXTtcblxuICBpZiAodHlwZW9mIG1heWJlSXRlcmF0b3IgPT09ICdmdW5jdGlvbicpIHtcbiAgICByZXR1cm4gbWF5YmVJdGVyYXRvcjtcbiAgfVxuXG4gIHJldHVybiBudWxsO1xufVxuXG4vKipcbiAqIEtlZXBzIHRyYWNrIG9mIHRoZSBjdXJyZW50IGRpc3BhdGNoZXIuXG4gKi9cbnZhciBSZWFjdEN1cnJlbnREaXNwYXRjaGVyID0ge1xuICAvKipcbiAgICogQGludGVybmFsXG4gICAqIEB0eXBlIHtSZWFjdENvbXBvbmVudH1cbiAgICovXG4gIGN1cnJlbnQ6IG51bGxcbn07XG5cbi8qKlxuICogS2VlcHMgdHJhY2sgb2YgdGhlIGN1cnJlbnQgYmF0Y2gncyBjb25maWd1cmF0aW9uIHN1Y2ggYXMgaG93IGxvbmcgYW4gdXBkYXRlXG4gKiBzaG91bGQgc3VzcGVuZCBmb3IgaWYgaXQgbmVlZHMgdG8uXG4gKi9cbnZhciBSZWFjdEN1cnJlbnRCYXRjaENvbmZpZyA9IHtcbiAgdHJhbnNpdGlvbjogbnVsbFxufTtcblxudmFyIFJlYWN0Q3VycmVudEFjdFF1ZXVlID0ge1xuICBjdXJyZW50OiBudWxsLFxuICAvLyBVc2VkIHRvIHJlcHJvZHVjZSBiZWhhdmlvciBvZiBgYmF0Y2hlZFVwZGF0ZXNgIGluIGxlZ2FjeSBtb2RlLlxuICBpc0JhdGNoaW5nTGVnYWN5OiBmYWxzZSxcbiAgZGlkU2NoZWR1bGVMZWdhY3lVcGRhdGU6IGZhbHNlXG59O1xuXG4vKipcbiAqIEtlZXBzIHRyYWNrIG9mIHRoZSBjdXJyZW50IG93bmVyLlxuICpcbiAqIFRoZSBjdXJyZW50IG93bmVyIGlzIHRoZSBjb21wb25lbnQgd2hvIHNob3VsZCBvd24gYW55IGNvbXBvbmVudHMgdGhhdCBhcmVcbiAqIGN1cnJlbnRseSBiZWluZyBjb25zdHJ1Y3RlZC5cbiAqL1xudmFyIFJlYWN0Q3VycmVudE93bmVyID0ge1xuICAvKipcbiAgICogQGludGVybmFsXG4gICAqIEB0eXBlIHtSZWFjdENvbXBvbmVudH1cbiAgICovXG4gIGN1cnJlbnQ6IG51bGxcbn07XG5cbnZhciBSZWFjdERlYnVnQ3VycmVudEZyYW1lID0ge307XG52YXIgY3VycmVudEV4dHJhU3RhY2tGcmFtZSA9IG51bGw7XG5mdW5jdGlvbiBzZXRFeHRyYVN0YWNrRnJhbWUoc3RhY2spIHtcbiAge1xuICAgIGN1cnJlbnRFeHRyYVN0YWNrRnJhbWUgPSBzdGFjaztcbiAgfVxufVxuXG57XG4gIFJlYWN0RGVidWdDdXJyZW50RnJhbWUuc2V0RXh0cmFTdGFja0ZyYW1lID0gZnVuY3Rpb24gKHN0YWNrKSB7XG4gICAge1xuICAgICAgY3VycmVudEV4dHJhU3RhY2tGcmFtZSA9IHN0YWNrO1xuICAgIH1cbiAgfTsgLy8gU3RhY2sgaW1wbGVtZW50YXRpb24gaW5qZWN0ZWQgYnkgdGhlIGN1cnJlbnQgcmVuZGVyZXIuXG5cblxuICBSZWFjdERlYnVnQ3VycmVudEZyYW1lLmdldEN1cnJlbnRTdGFjayA9IG51bGw7XG5cbiAgUmVhY3REZWJ1Z0N1cnJlbnRGcmFtZS5nZXRTdGFja0FkZGVuZHVtID0gZnVuY3Rpb24gKCkge1xuICAgIHZhciBzdGFjayA9ICcnOyAvLyBBZGQgYW4gZXh0cmEgdG9wIGZyYW1lIHdoaWxlIGFuIGVsZW1lbnQgaXMgYmVpbmcgdmFsaWRhdGVkXG5cbiAgICBpZiAoY3VycmVudEV4dHJhU3RhY2tGcmFtZSkge1xuICAgICAgc3RhY2sgKz0gY3VycmVudEV4dHJhU3RhY2tGcmFtZTtcbiAgICB9IC8vIERlbGVnYXRlIHRvIHRoZSBpbmplY3RlZCByZW5kZXJlci1zcGVjaWZpYyBpbXBsZW1lbnRhdGlvblxuXG5cbiAgICB2YXIgaW1wbCA9IFJlYWN0RGVidWdDdXJyZW50RnJhbWUuZ2V0Q3VycmVudFN0YWNrO1xuXG4gICAgaWYgKGltcGwpIHtcbiAgICAgIHN0YWNrICs9IGltcGwoKSB8fCAnJztcbiAgICB9XG5cbiAgICByZXR1cm4gc3RhY2s7XG4gIH07XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbnZhciBlbmFibGVTY29wZUFQSSA9IGZhbHNlOyAvLyBFeHBlcmltZW50YWwgQ3JlYXRlIEV2ZW50IEhhbmRsZSBBUEkuXG52YXIgZW5hYmxlQ2FjaGVFbGVtZW50ID0gZmFsc2U7XG52YXIgZW5hYmxlVHJhbnNpdGlvblRyYWNpbmcgPSBmYWxzZTsgLy8gTm8ga25vd24gYnVncywgYnV0IG5lZWRzIHBlcmZvcm1hbmNlIHRlc3RpbmdcblxudmFyIGVuYWJsZUxlZ2FjeUhpZGRlbiA9IGZhbHNlOyAvLyBFbmFibGVzIHVuc3RhYmxlX2F2b2lkVGhpc0ZhbGxiYWNrIGZlYXR1cmUgaW4gRmliZXJcbi8vIHN0dWZmLiBJbnRlbmRlZCB0byBlbmFibGUgUmVhY3QgY29yZSBtZW1iZXJzIHRvIG1vcmUgZWFzaWx5IGRlYnVnIHNjaGVkdWxpbmdcbi8vIGlzc3VlcyBpbiBERVYgYnVpbGRzLlxuXG52YXIgZW5hYmxlRGVidWdUcmFjaW5nID0gZmFsc2U7IC8vIFRyYWNrIHdoaWNoIEZpYmVyKHMpIHNjaGVkdWxlIHJlbmRlciB3b3JrLlxuXG52YXIgUmVhY3RTaGFyZWRJbnRlcm5hbHMgPSB7XG4gIFJlYWN0Q3VycmVudERpc3BhdGNoZXI6IFJlYWN0Q3VycmVudERpc3BhdGNoZXIsXG4gIFJlYWN0Q3VycmVudEJhdGNoQ29uZmlnOiBSZWFjdEN1cnJlbnRCYXRjaENvbmZpZyxcbiAgUmVhY3RDdXJyZW50T3duZXI6IFJlYWN0Q3VycmVudE93bmVyXG59O1xuXG57XG4gIFJlYWN0U2hhcmVkSW50ZXJuYWxzLlJlYWN0RGVidWdDdXJyZW50RnJhbWUgPSBSZWFjdERlYnVnQ3VycmVudEZyYW1lO1xuICBSZWFjdFNoYXJlZEludGVybmFscy5SZWFjdEN1cnJlbnRBY3RRdWV1ZSA9IFJlYWN0Q3VycmVudEFjdFF1ZXVlO1xufVxuXG4vLyBieSBjYWxscyB0byB0aGVzZSBtZXRob2RzIGJ5IGEgQmFiZWwgcGx1Z2luLlxuLy9cbi8vIEluIFBST0QgKG9yIGluIHBhY2thZ2VzIHdpdGhvdXQgYWNjZXNzIHRvIFJlYWN0IGludGVybmFscyksXG4vLyB0aGV5IGFyZSBsZWZ0IGFzIHRoZXkgYXJlIGluc3RlYWQuXG5cbmZ1bmN0aW9uIHdhcm4oZm9ybWF0KSB7XG4gIHtcbiAgICB7XG4gICAgICBmb3IgKHZhciBfbGVuID0gYXJndW1lbnRzLmxlbmd0aCwgYXJncyA9IG5ldyBBcnJheShfbGVuID4gMSA/IF9sZW4gLSAxIDogMCksIF9rZXkgPSAxOyBfa2V5IDwgX2xlbjsgX2tleSsrKSB7XG4gICAgICAgIGFyZ3NbX2tleSAtIDFdID0gYXJndW1lbnRzW19rZXldO1xuICAgICAgfVxuXG4gICAgICBwcmludFdhcm5pbmcoJ3dhcm4nLCBmb3JtYXQsIGFyZ3MpO1xuICAgIH1cbiAgfVxufVxuZnVuY3Rpb24gZXJyb3IoZm9ybWF0KSB7XG4gIHtcbiAgICB7XG4gICAgICBmb3IgKHZhciBfbGVuMiA9IGFyZ3VtZW50cy5sZW5ndGgsIGFyZ3MgPSBuZXcgQXJyYXkoX2xlbjIgPiAxID8gX2xlbjIgLSAxIDogMCksIF9rZXkyID0gMTsgX2tleTIgPCBfbGVuMjsgX2tleTIrKykge1xuICAgICAgICBhcmdzW19rZXkyIC0gMV0gPSBhcmd1bWVudHNbX2tleTJdO1xuICAgICAgfVxuXG4gICAgICBwcmludFdhcm5pbmcoJ2Vycm9yJywgZm9ybWF0LCBhcmdzKTtcbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gcHJpbnRXYXJuaW5nKGxldmVsLCBmb3JtYXQsIGFyZ3MpIHtcbiAgLy8gV2hlbiBjaGFuZ2luZyB0aGlzIGxvZ2ljLCB5b3UgbWlnaHQgd2FudCB0byBhbHNvXG4gIC8vIHVwZGF0ZSBjb25zb2xlV2l0aFN0YWNrRGV2Lnd3dy5qcyBhcyB3ZWxsLlxuICB7XG4gICAgdmFyIFJlYWN0RGVidWdDdXJyZW50RnJhbWUgPSBSZWFjdFNoYXJlZEludGVybmFscy5SZWFjdERlYnVnQ3VycmVudEZyYW1lO1xuICAgIHZhciBzdGFjayA9IFJlYWN0RGVidWdDdXJyZW50RnJhbWUuZ2V0U3RhY2tBZGRlbmR1bSgpO1xuXG4gICAgaWYgKHN0YWNrICE9PSAnJykge1xuICAgICAgZm9ybWF0ICs9ICclcyc7XG4gICAgICBhcmdzID0gYXJncy5jb25jYXQoW3N0YWNrXSk7XG4gICAgfSAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgcmVhY3QtaW50ZXJuYWwvc2FmZS1zdHJpbmctY29lcmNpb25cblxuXG4gICAgdmFyIGFyZ3NXaXRoRm9ybWF0ID0gYXJncy5tYXAoZnVuY3Rpb24gKGl0ZW0pIHtcbiAgICAgIHJldHVybiBTdHJpbmcoaXRlbSk7XG4gICAgfSk7IC8vIENhcmVmdWw6IFJOIGN1cnJlbnRseSBkZXBlbmRzIG9uIHRoaXMgcHJlZml4XG5cbiAgICBhcmdzV2l0aEZvcm1hdC51bnNoaWZ0KCdXYXJuaW5nOiAnICsgZm9ybWF0KTsgLy8gV2UgaW50ZW50aW9uYWxseSBkb24ndCB1c2Ugc3ByZWFkIChvciAuYXBwbHkpIGRpcmVjdGx5IGJlY2F1c2UgaXRcbiAgICAvLyBicmVha3MgSUU5OiBodHRwczovL2dpdGh1Yi5jb20vZmFjZWJvb2svcmVhY3QvaXNzdWVzLzEzNjEwXG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIHJlYWN0LWludGVybmFsL25vLXByb2R1Y3Rpb24tbG9nZ2luZ1xuXG4gICAgRnVuY3Rpb24ucHJvdG90eXBlLmFwcGx5LmNhbGwoY29uc29sZVtsZXZlbF0sIGNvbnNvbGUsIGFyZ3NXaXRoRm9ybWF0KTtcbiAgfVxufVxuXG52YXIgZGlkV2FyblN0YXRlVXBkYXRlRm9yVW5tb3VudGVkQ29tcG9uZW50ID0ge307XG5cbmZ1bmN0aW9uIHdhcm5Ob29wKHB1YmxpY0luc3RhbmNlLCBjYWxsZXJOYW1lKSB7XG4gIHtcbiAgICB2YXIgX2NvbnN0cnVjdG9yID0gcHVibGljSW5zdGFuY2UuY29uc3RydWN0b3I7XG4gICAgdmFyIGNvbXBvbmVudE5hbWUgPSBfY29uc3RydWN0b3IgJiYgKF9jb25zdHJ1Y3Rvci5kaXNwbGF5TmFtZSB8fCBfY29uc3RydWN0b3IubmFtZSkgfHwgJ1JlYWN0Q2xhc3MnO1xuICAgIHZhciB3YXJuaW5nS2V5ID0gY29tcG9uZW50TmFtZSArIFwiLlwiICsgY2FsbGVyTmFtZTtcblxuICAgIGlmIChkaWRXYXJuU3RhdGVVcGRhdGVGb3JVbm1vdW50ZWRDb21wb25lbnRbd2FybmluZ0tleV0pIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBlcnJvcihcIkNhbid0IGNhbGwgJXMgb24gYSBjb21wb25lbnQgdGhhdCBpcyBub3QgeWV0IG1vdW50ZWQuIFwiICsgJ1RoaXMgaXMgYSBuby1vcCwgYnV0IGl0IG1pZ2h0IGluZGljYXRlIGEgYnVnIGluIHlvdXIgYXBwbGljYXRpb24uICcgKyAnSW5zdGVhZCwgYXNzaWduIHRvIGB0aGlzLnN0YXRlYCBkaXJlY3RseSBvciBkZWZpbmUgYSBgc3RhdGUgPSB7fTtgICcgKyAnY2xhc3MgcHJvcGVydHkgd2l0aCB0aGUgZGVzaXJlZCBzdGF0ZSBpbiB0aGUgJXMgY29tcG9uZW50LicsIGNhbGxlck5hbWUsIGNvbXBvbmVudE5hbWUpO1xuXG4gICAgZGlkV2FyblN0YXRlVXBkYXRlRm9yVW5tb3VudGVkQ29tcG9uZW50W3dhcm5pbmdLZXldID0gdHJ1ZTtcbiAgfVxufVxuLyoqXG4gKiBUaGlzIGlzIHRoZSBhYnN0cmFjdCBBUEkgZm9yIGFuIHVwZGF0ZSBxdWV1ZS5cbiAqL1xuXG5cbnZhciBSZWFjdE5vb3BVcGRhdGVRdWV1ZSA9IHtcbiAgLyoqXG4gICAqIENoZWNrcyB3aGV0aGVyIG9yIG5vdCB0aGlzIGNvbXBvc2l0ZSBjb21wb25lbnQgaXMgbW91bnRlZC5cbiAgICogQHBhcmFtIHtSZWFjdENsYXNzfSBwdWJsaWNJbnN0YW5jZSBUaGUgaW5zdGFuY2Ugd2Ugd2FudCB0byB0ZXN0LlxuICAgKiBAcmV0dXJuIHtib29sZWFufSBUcnVlIGlmIG1vdW50ZWQsIGZhbHNlIG90aGVyd2lzZS5cbiAgICogQHByb3RlY3RlZFxuICAgKiBAZmluYWxcbiAgICovXG4gIGlzTW91bnRlZDogZnVuY3Rpb24gKHB1YmxpY0luc3RhbmNlKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9LFxuXG4gIC8qKlxuICAgKiBGb3JjZXMgYW4gdXBkYXRlLiBUaGlzIHNob3VsZCBvbmx5IGJlIGludm9rZWQgd2hlbiBpdCBpcyBrbm93biB3aXRoXG4gICAqIGNlcnRhaW50eSB0aGF0IHdlIGFyZSAqKm5vdCoqIGluIGEgRE9NIHRyYW5zYWN0aW9uLlxuICAgKlxuICAgKiBZb3UgbWF5IHdhbnQgdG8gY2FsbCB0aGlzIHdoZW4geW91IGtub3cgdGhhdCBzb21lIGRlZXBlciBhc3BlY3Qgb2YgdGhlXG4gICAqIGNvbXBvbmVudCdzIHN0YXRlIGhhcyBjaGFuZ2VkIGJ1dCBgc2V0U3RhdGVgIHdhcyBub3QgY2FsbGVkLlxuICAgKlxuICAgKiBUaGlzIHdpbGwgbm90IGludm9rZSBgc2hvdWxkQ29tcG9uZW50VXBkYXRlYCwgYnV0IGl0IHdpbGwgaW52b2tlXG4gICAqIGBjb21wb25lbnRXaWxsVXBkYXRlYCBhbmQgYGNvbXBvbmVudERpZFVwZGF0ZWAuXG4gICAqXG4gICAqIEBwYXJhbSB7UmVhY3RDbGFzc30gcHVibGljSW5zdGFuY2UgVGhlIGluc3RhbmNlIHRoYXQgc2hvdWxkIHJlcmVuZGVyLlxuICAgKiBAcGFyYW0gez9mdW5jdGlvbn0gY2FsbGJhY2sgQ2FsbGVkIGFmdGVyIGNvbXBvbmVudCBpcyB1cGRhdGVkLlxuICAgKiBAcGFyYW0gez9zdHJpbmd9IGNhbGxlck5hbWUgbmFtZSBvZiB0aGUgY2FsbGluZyBmdW5jdGlvbiBpbiB0aGUgcHVibGljIEFQSS5cbiAgICogQGludGVybmFsXG4gICAqL1xuICBlbnF1ZXVlRm9yY2VVcGRhdGU6IGZ1bmN0aW9uIChwdWJsaWNJbnN0YW5jZSwgY2FsbGJhY2ssIGNhbGxlck5hbWUpIHtcbiAgICB3YXJuTm9vcChwdWJsaWNJbnN0YW5jZSwgJ2ZvcmNlVXBkYXRlJyk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIFJlcGxhY2VzIGFsbCBvZiB0aGUgc3RhdGUuIEFsd2F5cyB1c2UgdGhpcyBvciBgc2V0U3RhdGVgIHRvIG11dGF0ZSBzdGF0ZS5cbiAgICogWW91IHNob3VsZCB0cmVhdCBgdGhpcy5zdGF0ZWAgYXMgaW1tdXRhYmxlLlxuICAgKlxuICAgKiBUaGVyZSBpcyBubyBndWFyYW50ZWUgdGhhdCBgdGhpcy5zdGF0ZWAgd2lsbCBiZSBpbW1lZGlhdGVseSB1cGRhdGVkLCBzb1xuICAgKiBhY2Nlc3NpbmcgYHRoaXMuc3RhdGVgIGFmdGVyIGNhbGxpbmcgdGhpcyBtZXRob2QgbWF5IHJldHVybiB0aGUgb2xkIHZhbHVlLlxuICAgKlxuICAgKiBAcGFyYW0ge1JlYWN0Q2xhc3N9IHB1YmxpY0luc3RhbmNlIFRoZSBpbnN0YW5jZSB0aGF0IHNob3VsZCByZXJlbmRlci5cbiAgICogQHBhcmFtIHtvYmplY3R9IGNvbXBsZXRlU3RhdGUgTmV4dCBzdGF0ZS5cbiAgICogQHBhcmFtIHs/ZnVuY3Rpb259IGNhbGxiYWNrIENhbGxlZCBhZnRlciBjb21wb25lbnQgaXMgdXBkYXRlZC5cbiAgICogQHBhcmFtIHs/c3RyaW5nfSBjYWxsZXJOYW1lIG5hbWUgb2YgdGhlIGNhbGxpbmcgZnVuY3Rpb24gaW4gdGhlIHB1YmxpYyBBUEkuXG4gICAqIEBpbnRlcm5hbFxuICAgKi9cbiAgZW5xdWV1ZVJlcGxhY2VTdGF0ZTogZnVuY3Rpb24gKHB1YmxpY0luc3RhbmNlLCBjb21wbGV0ZVN0YXRlLCBjYWxsYmFjaywgY2FsbGVyTmFtZSkge1xuICAgIHdhcm5Ob29wKHB1YmxpY0luc3RhbmNlLCAncmVwbGFjZVN0YXRlJyk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIFNldHMgYSBzdWJzZXQgb2YgdGhlIHN0YXRlLiBUaGlzIG9ubHkgZXhpc3RzIGJlY2F1c2UgX3BlbmRpbmdTdGF0ZSBpc1xuICAgKiBpbnRlcm5hbC4gVGhpcyBwcm92aWRlcyBhIG1lcmdpbmcgc3RyYXRlZ3kgdGhhdCBpcyBub3QgYXZhaWxhYmxlIHRvIGRlZXBcbiAgICogcHJvcGVydGllcyB3aGljaCBpcyBjb25mdXNpbmcuIFRPRE86IEV4cG9zZSBwZW5kaW5nU3RhdGUgb3IgZG9uJ3QgdXNlIGl0XG4gICAqIGR1cmluZyB0aGUgbWVyZ2UuXG4gICAqXG4gICAqIEBwYXJhbSB7UmVhY3RDbGFzc30gcHVibGljSW5zdGFuY2UgVGhlIGluc3RhbmNlIHRoYXQgc2hvdWxkIHJlcmVuZGVyLlxuICAgKiBAcGFyYW0ge29iamVjdH0gcGFydGlhbFN0YXRlIE5leHQgcGFydGlhbCBzdGF0ZSB0byBiZSBtZXJnZWQgd2l0aCBzdGF0ZS5cbiAgICogQHBhcmFtIHs/ZnVuY3Rpb259IGNhbGxiYWNrIENhbGxlZCBhZnRlciBjb21wb25lbnQgaXMgdXBkYXRlZC5cbiAgICogQHBhcmFtIHs/c3RyaW5nfSBOYW1lIG9mIHRoZSBjYWxsaW5nIGZ1bmN0aW9uIGluIHRoZSBwdWJsaWMgQVBJLlxuICAgKiBAaW50ZXJuYWxcbiAgICovXG4gIGVucXVldWVTZXRTdGF0ZTogZnVuY3Rpb24gKHB1YmxpY0luc3RhbmNlLCBwYXJ0aWFsU3RhdGUsIGNhbGxiYWNrLCBjYWxsZXJOYW1lKSB7XG4gICAgd2Fybk5vb3AocHVibGljSW5zdGFuY2UsICdzZXRTdGF0ZScpO1xuICB9XG59O1xuXG52YXIgYXNzaWduID0gT2JqZWN0LmFzc2lnbjtcblxudmFyIGVtcHR5T2JqZWN0ID0ge307XG5cbntcbiAgT2JqZWN0LmZyZWV6ZShlbXB0eU9iamVjdCk7XG59XG4vKipcbiAqIEJhc2UgY2xhc3MgaGVscGVycyBmb3IgdGhlIHVwZGF0aW5nIHN0YXRlIG9mIGEgY29tcG9uZW50LlxuICovXG5cblxuZnVuY3Rpb24gQ29tcG9uZW50KHByb3BzLCBjb250ZXh0LCB1cGRhdGVyKSB7XG4gIHRoaXMucHJvcHMgPSBwcm9wcztcbiAgdGhpcy5jb250ZXh0ID0gY29udGV4dDsgLy8gSWYgYSBjb21wb25lbnQgaGFzIHN0cmluZyByZWZzLCB3ZSB3aWxsIGFzc2lnbiBhIGRpZmZlcmVudCBvYmplY3QgbGF0ZXIuXG5cbiAgdGhpcy5yZWZzID0gZW1wdHlPYmplY3Q7IC8vIFdlIGluaXRpYWxpemUgdGhlIGRlZmF1bHQgdXBkYXRlciBidXQgdGhlIHJlYWwgb25lIGdldHMgaW5qZWN0ZWQgYnkgdGhlXG4gIC8vIHJlbmRlcmVyLlxuXG4gIHRoaXMudXBkYXRlciA9IHVwZGF0ZXIgfHwgUmVhY3ROb29wVXBkYXRlUXVldWU7XG59XG5cbkNvbXBvbmVudC5wcm90b3R5cGUuaXNSZWFjdENvbXBvbmVudCA9IHt9O1xuLyoqXG4gKiBTZXRzIGEgc3Vic2V0IG9mIHRoZSBzdGF0ZS4gQWx3YXlzIHVzZSB0aGlzIHRvIG11dGF0ZVxuICogc3RhdGUuIFlvdSBzaG91bGQgdHJlYXQgYHRoaXMuc3RhdGVgIGFzIGltbXV0YWJsZS5cbiAqXG4gKiBUaGVyZSBpcyBubyBndWFyYW50ZWUgdGhhdCBgdGhpcy5zdGF0ZWAgd2lsbCBiZSBpbW1lZGlhdGVseSB1cGRhdGVkLCBzb1xuICogYWNjZXNzaW5nIGB0aGlzLnN0YXRlYCBhZnRlciBjYWxsaW5nIHRoaXMgbWV0aG9kIG1heSByZXR1cm4gdGhlIG9sZCB2YWx1ZS5cbiAqXG4gKiBUaGVyZSBpcyBubyBndWFyYW50ZWUgdGhhdCBjYWxscyB0byBgc2V0U3RhdGVgIHdpbGwgcnVuIHN5bmNocm9ub3VzbHksXG4gKiBhcyB0aGV5IG1heSBldmVudHVhbGx5IGJlIGJhdGNoZWQgdG9nZXRoZXIuICBZb3UgY2FuIHByb3ZpZGUgYW4gb3B0aW9uYWxcbiAqIGNhbGxiYWNrIHRoYXQgd2lsbCBiZSBleGVjdXRlZCB3aGVuIHRoZSBjYWxsIHRvIHNldFN0YXRlIGlzIGFjdHVhbGx5XG4gKiBjb21wbGV0ZWQuXG4gKlxuICogV2hlbiBhIGZ1bmN0aW9uIGlzIHByb3ZpZGVkIHRvIHNldFN0YXRlLCBpdCB3aWxsIGJlIGNhbGxlZCBhdCBzb21lIHBvaW50IGluXG4gKiB0aGUgZnV0dXJlIChub3Qgc3luY2hyb25vdXNseSkuIEl0IHdpbGwgYmUgY2FsbGVkIHdpdGggdGhlIHVwIHRvIGRhdGVcbiAqIGNvbXBvbmVudCBhcmd1bWVudHMgKHN0YXRlLCBwcm9wcywgY29udGV4dCkuIFRoZXNlIHZhbHVlcyBjYW4gYmUgZGlmZmVyZW50XG4gKiBmcm9tIHRoaXMuKiBiZWNhdXNlIHlvdXIgZnVuY3Rpb24gbWF5IGJlIGNhbGxlZCBhZnRlciByZWNlaXZlUHJvcHMgYnV0IGJlZm9yZVxuICogc2hvdWxkQ29tcG9uZW50VXBkYXRlLCBhbmQgdGhpcyBuZXcgc3RhdGUsIHByb3BzLCBhbmQgY29udGV4dCB3aWxsIG5vdCB5ZXQgYmVcbiAqIGFzc2lnbmVkIHRvIHRoaXMuXG4gKlxuICogQHBhcmFtIHtvYmplY3R8ZnVuY3Rpb259IHBhcnRpYWxTdGF0ZSBOZXh0IHBhcnRpYWwgc3RhdGUgb3IgZnVuY3Rpb24gdG9cbiAqICAgICAgICBwcm9kdWNlIG5leHQgcGFydGlhbCBzdGF0ZSB0byBiZSBtZXJnZWQgd2l0aCBjdXJyZW50IHN0YXRlLlxuICogQHBhcmFtIHs/ZnVuY3Rpb259IGNhbGxiYWNrIENhbGxlZCBhZnRlciBzdGF0ZSBpcyB1cGRhdGVkLlxuICogQGZpbmFsXG4gKiBAcHJvdGVjdGVkXG4gKi9cblxuQ29tcG9uZW50LnByb3RvdHlwZS5zZXRTdGF0ZSA9IGZ1bmN0aW9uIChwYXJ0aWFsU3RhdGUsIGNhbGxiYWNrKSB7XG4gIGlmICh0eXBlb2YgcGFydGlhbFN0YXRlICE9PSAnb2JqZWN0JyAmJiB0eXBlb2YgcGFydGlhbFN0YXRlICE9PSAnZnVuY3Rpb24nICYmIHBhcnRpYWxTdGF0ZSAhPSBudWxsKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdzZXRTdGF0ZSguLi4pOiB0YWtlcyBhbiBvYmplY3Qgb2Ygc3RhdGUgdmFyaWFibGVzIHRvIHVwZGF0ZSBvciBhICcgKyAnZnVuY3Rpb24gd2hpY2ggcmV0dXJucyBhbiBvYmplY3Qgb2Ygc3RhdGUgdmFyaWFibGVzLicpO1xuICB9XG5cbiAgdGhpcy51cGRhdGVyLmVucXVldWVTZXRTdGF0ZSh0aGlzLCBwYXJ0aWFsU3RhdGUsIGNhbGxiYWNrLCAnc2V0U3RhdGUnKTtcbn07XG4vKipcbiAqIEZvcmNlcyBhbiB1cGRhdGUuIFRoaXMgc2hvdWxkIG9ubHkgYmUgaW52b2tlZCB3aGVuIGl0IGlzIGtub3duIHdpdGhcbiAqIGNlcnRhaW50eSB0aGF0IHdlIGFyZSAqKm5vdCoqIGluIGEgRE9NIHRyYW5zYWN0aW9uLlxuICpcbiAqIFlvdSBtYXkgd2FudCB0byBjYWxsIHRoaXMgd2hlbiB5b3Uga25vdyB0aGF0IHNvbWUgZGVlcGVyIGFzcGVjdCBvZiB0aGVcbiAqIGNvbXBvbmVudCdzIHN0YXRlIGhhcyBjaGFuZ2VkIGJ1dCBgc2V0U3RhdGVgIHdhcyBub3QgY2FsbGVkLlxuICpcbiAqIFRoaXMgd2lsbCBub3QgaW52b2tlIGBzaG91bGRDb21wb25lbnRVcGRhdGVgLCBidXQgaXQgd2lsbCBpbnZva2VcbiAqIGBjb21wb25lbnRXaWxsVXBkYXRlYCBhbmQgYGNvbXBvbmVudERpZFVwZGF0ZWAuXG4gKlxuICogQHBhcmFtIHs/ZnVuY3Rpb259IGNhbGxiYWNrIENhbGxlZCBhZnRlciB1cGRhdGUgaXMgY29tcGxldGUuXG4gKiBAZmluYWxcbiAqIEBwcm90ZWN0ZWRcbiAqL1xuXG5cbkNvbXBvbmVudC5wcm90b3R5cGUuZm9yY2VVcGRhdGUgPSBmdW5jdGlvbiAoY2FsbGJhY2spIHtcbiAgdGhpcy51cGRhdGVyLmVucXVldWVGb3JjZVVwZGF0ZSh0aGlzLCBjYWxsYmFjaywgJ2ZvcmNlVXBkYXRlJyk7XG59O1xuLyoqXG4gKiBEZXByZWNhdGVkIEFQSXMuIFRoZXNlIEFQSXMgdXNlZCB0byBleGlzdCBvbiBjbGFzc2ljIFJlYWN0IGNsYXNzZXMgYnV0IHNpbmNlXG4gKiB3ZSB3b3VsZCBsaWtlIHRvIGRlcHJlY2F0ZSB0aGVtLCB3ZSdyZSBub3QgZ29pbmcgdG8gbW92ZSB0aGVtIG92ZXIgdG8gdGhpc1xuICogbW9kZXJuIGJhc2UgY2xhc3MuIEluc3RlYWQsIHdlIGRlZmluZSBhIGdldHRlciB0aGF0IHdhcm5zIGlmIGl0J3MgYWNjZXNzZWQuXG4gKi9cblxuXG57XG4gIHZhciBkZXByZWNhdGVkQVBJcyA9IHtcbiAgICBpc01vdW50ZWQ6IFsnaXNNb3VudGVkJywgJ0luc3RlYWQsIG1ha2Ugc3VyZSB0byBjbGVhbiB1cCBzdWJzY3JpcHRpb25zIGFuZCBwZW5kaW5nIHJlcXVlc3RzIGluICcgKyAnY29tcG9uZW50V2lsbFVubW91bnQgdG8gcHJldmVudCBtZW1vcnkgbGVha3MuJ10sXG4gICAgcmVwbGFjZVN0YXRlOiBbJ3JlcGxhY2VTdGF0ZScsICdSZWZhY3RvciB5b3VyIGNvZGUgdG8gdXNlIHNldFN0YXRlIGluc3RlYWQgKHNlZSAnICsgJ2h0dHBzOi8vZ2l0aHViLmNvbS9mYWNlYm9vay9yZWFjdC9pc3N1ZXMvMzIzNikuJ11cbiAgfTtcblxuICB2YXIgZGVmaW5lRGVwcmVjYXRpb25XYXJuaW5nID0gZnVuY3Rpb24gKG1ldGhvZE5hbWUsIGluZm8pIHtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoQ29tcG9uZW50LnByb3RvdHlwZSwgbWV0aG9kTmFtZSwge1xuICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHdhcm4oJyVzKC4uLikgaXMgZGVwcmVjYXRlZCBpbiBwbGFpbiBKYXZhU2NyaXB0IFJlYWN0IGNsYXNzZXMuICVzJywgaW5mb1swXSwgaW5mb1sxXSk7XG5cbiAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcblxuICBmb3IgKHZhciBmbk5hbWUgaW4gZGVwcmVjYXRlZEFQSXMpIHtcbiAgICBpZiAoZGVwcmVjYXRlZEFQSXMuaGFzT3duUHJvcGVydHkoZm5OYW1lKSkge1xuICAgICAgZGVmaW5lRGVwcmVjYXRpb25XYXJuaW5nKGZuTmFtZSwgZGVwcmVjYXRlZEFQSXNbZm5OYW1lXSk7XG4gICAgfVxuICB9XG59XG5cbmZ1bmN0aW9uIENvbXBvbmVudER1bW15KCkge31cblxuQ29tcG9uZW50RHVtbXkucHJvdG90eXBlID0gQ29tcG9uZW50LnByb3RvdHlwZTtcbi8qKlxuICogQ29udmVuaWVuY2UgY29tcG9uZW50IHdpdGggZGVmYXVsdCBzaGFsbG93IGVxdWFsaXR5IGNoZWNrIGZvciBzQ1UuXG4gKi9cblxuZnVuY3Rpb24gUHVyZUNvbXBvbmVudChwcm9wcywgY29udGV4dCwgdXBkYXRlcikge1xuICB0aGlzLnByb3BzID0gcHJvcHM7XG4gIHRoaXMuY29udGV4dCA9IGNvbnRleHQ7IC8vIElmIGEgY29tcG9uZW50IGhhcyBzdHJpbmcgcmVmcywgd2Ugd2lsbCBhc3NpZ24gYSBkaWZmZXJlbnQgb2JqZWN0IGxhdGVyLlxuXG4gIHRoaXMucmVmcyA9IGVtcHR5T2JqZWN0O1xuICB0aGlzLnVwZGF0ZXIgPSB1cGRhdGVyIHx8IFJlYWN0Tm9vcFVwZGF0ZVF1ZXVlO1xufVxuXG52YXIgcHVyZUNvbXBvbmVudFByb3RvdHlwZSA9IFB1cmVDb21wb25lbnQucHJvdG90eXBlID0gbmV3IENvbXBvbmVudER1bW15KCk7XG5wdXJlQ29tcG9uZW50UHJvdG90eXBlLmNvbnN0cnVjdG9yID0gUHVyZUNvbXBvbmVudDsgLy8gQXZvaWQgYW4gZXh0cmEgcHJvdG90eXBlIGp1bXAgZm9yIHRoZXNlIG1ldGhvZHMuXG5cbmFzc2lnbihwdXJlQ29tcG9uZW50UHJvdG90eXBlLCBDb21wb25lbnQucHJvdG90eXBlKTtcbnB1cmVDb21wb25lbnRQcm90b3R5cGUuaXNQdXJlUmVhY3RDb21wb25lbnQgPSB0cnVlO1xuXG4vLyBhbiBpbW11dGFibGUgb2JqZWN0IHdpdGggYSBzaW5nbGUgbXV0YWJsZSB2YWx1ZVxuZnVuY3Rpb24gY3JlYXRlUmVmKCkge1xuICB2YXIgcmVmT2JqZWN0ID0ge1xuICAgIGN1cnJlbnQ6IG51bGxcbiAgfTtcblxuICB7XG4gICAgT2JqZWN0LnNlYWwocmVmT2JqZWN0KTtcbiAgfVxuXG4gIHJldHVybiByZWZPYmplY3Q7XG59XG5cbnZhciBpc0FycmF5SW1wbCA9IEFycmF5LmlzQXJyYXk7IC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1yZWRlY2xhcmVcblxuZnVuY3Rpb24gaXNBcnJheShhKSB7XG4gIHJldHVybiBpc0FycmF5SW1wbChhKTtcbn1cblxuLypcbiAqIFRoZSBgJycgKyB2YWx1ZWAgcGF0dGVybiAodXNlZCBpbiBpbiBwZXJmLXNlbnNpdGl2ZSBjb2RlKSB0aHJvd3MgZm9yIFN5bWJvbFxuICogYW5kIFRlbXBvcmFsLiogdHlwZXMuIFNlZSBodHRwczovL2dpdGh1Yi5jb20vZmFjZWJvb2svcmVhY3QvcHVsbC8yMjA2NC5cbiAqXG4gKiBUaGUgZnVuY3Rpb25zIGluIHRoaXMgbW9kdWxlIHdpbGwgdGhyb3cgYW4gZWFzaWVyLXRvLXVuZGVyc3RhbmQsXG4gKiBlYXNpZXItdG8tZGVidWcgZXhjZXB0aW9uIHdpdGggYSBjbGVhciBlcnJvcnMgbWVzc2FnZSBtZXNzYWdlIGV4cGxhaW5pbmcgdGhlXG4gKiBwcm9ibGVtLiAoSW5zdGVhZCBvZiBhIGNvbmZ1c2luZyBleGNlcHRpb24gdGhyb3duIGluc2lkZSB0aGUgaW1wbGVtZW50YXRpb25cbiAqIG9mIHRoZSBgdmFsdWVgIG9iamVjdCkuXG4gKi9cbi8vICRGbG93Rml4TWUgb25seSBjYWxsZWQgaW4gREVWLCBzbyB2b2lkIHJldHVybiBpcyBub3QgcG9zc2libGUuXG5mdW5jdGlvbiB0eXBlTmFtZSh2YWx1ZSkge1xuICB7XG4gICAgLy8gdG9TdHJpbmdUYWcgaXMgbmVlZGVkIGZvciBuYW1lc3BhY2VkIHR5cGVzIGxpa2UgVGVtcG9yYWwuSW5zdGFudFxuICAgIHZhciBoYXNUb1N0cmluZ1RhZyA9IHR5cGVvZiBTeW1ib2wgPT09ICdmdW5jdGlvbicgJiYgU3ltYm9sLnRvU3RyaW5nVGFnO1xuICAgIHZhciB0eXBlID0gaGFzVG9TdHJpbmdUYWcgJiYgdmFsdWVbU3ltYm9sLnRvU3RyaW5nVGFnXSB8fCB2YWx1ZS5jb25zdHJ1Y3Rvci5uYW1lIHx8ICdPYmplY3QnO1xuICAgIHJldHVybiB0eXBlO1xuICB9XG59IC8vICRGbG93Rml4TWUgb25seSBjYWxsZWQgaW4gREVWLCBzbyB2b2lkIHJldHVybiBpcyBub3QgcG9zc2libGUuXG5cblxuZnVuY3Rpb24gd2lsbENvZXJjaW9uVGhyb3codmFsdWUpIHtcbiAge1xuICAgIHRyeSB7XG4gICAgICB0ZXN0U3RyaW5nQ29lcmNpb24odmFsdWUpO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiB0ZXN0U3RyaW5nQ29lcmNpb24odmFsdWUpIHtcbiAgLy8gSWYgeW91IGVuZGVkIHVwIGhlcmUgYnkgZm9sbG93aW5nIGFuIGV4Y2VwdGlvbiBjYWxsIHN0YWNrLCBoZXJlJ3Mgd2hhdCdzXG4gIC8vIGhhcHBlbmVkOiB5b3Ugc3VwcGxpZWQgYW4gb2JqZWN0IG9yIHN5bWJvbCB2YWx1ZSB0byBSZWFjdCAoYXMgYSBwcm9wLCBrZXksXG4gIC8vIERPTSBhdHRyaWJ1dGUsIENTUyBwcm9wZXJ0eSwgc3RyaW5nIHJlZiwgZXRjLikgYW5kIHdoZW4gUmVhY3QgdHJpZWQgdG9cbiAgLy8gY29lcmNlIGl0IHRvIGEgc3RyaW5nIHVzaW5nIGAnJyArIHZhbHVlYCwgYW4gZXhjZXB0aW9uIHdhcyB0aHJvd24uXG4gIC8vXG4gIC8vIFRoZSBtb3N0IGNvbW1vbiB0eXBlcyB0aGF0IHdpbGwgY2F1c2UgdGhpcyBleGNlcHRpb24gYXJlIGBTeW1ib2xgIGluc3RhbmNlc1xuICAvLyBhbmQgVGVtcG9yYWwgb2JqZWN0cyBsaWtlIGBUZW1wb3JhbC5JbnN0YW50YC4gQnV0IGFueSBvYmplY3QgdGhhdCBoYXMgYVxuICAvLyBgdmFsdWVPZmAgb3IgYFtTeW1ib2wudG9QcmltaXRpdmVdYCBtZXRob2QgdGhhdCB0aHJvd3Mgd2lsbCBhbHNvIGNhdXNlIHRoaXNcbiAgLy8gZXhjZXB0aW9uLiAoTGlicmFyeSBhdXRob3JzIGRvIHRoaXMgdG8gcHJldmVudCB1c2VycyBmcm9tIHVzaW5nIGJ1aWx0LWluXG4gIC8vIG51bWVyaWMgb3BlcmF0b3JzIGxpa2UgYCtgIG9yIGNvbXBhcmlzb24gb3BlcmF0b3JzIGxpa2UgYD49YCBiZWNhdXNlIGN1c3RvbVxuICAvLyBtZXRob2RzIGFyZSBuZWVkZWQgdG8gcGVyZm9ybSBhY2N1cmF0ZSBhcml0aG1ldGljIG9yIGNvbXBhcmlzb24uKVxuICAvL1xuICAvLyBUbyBmaXggdGhlIHByb2JsZW0sIGNvZXJjZSB0aGlzIG9iamVjdCBvciBzeW1ib2wgdmFsdWUgdG8gYSBzdHJpbmcgYmVmb3JlXG4gIC8vIHBhc3NpbmcgaXQgdG8gUmVhY3QuIFRoZSBtb3N0IHJlbGlhYmxlIHdheSBpcyB1c3VhbGx5IGBTdHJpbmcodmFsdWUpYC5cbiAgLy9cbiAgLy8gVG8gZmluZCB3aGljaCB2YWx1ZSBpcyB0aHJvd2luZywgY2hlY2sgdGhlIGJyb3dzZXIgb3IgZGVidWdnZXIgY29uc29sZS5cbiAgLy8gQmVmb3JlIHRoaXMgZXhjZXB0aW9uIHdhcyB0aHJvd24sIHRoZXJlIHNob3VsZCBiZSBgY29uc29sZS5lcnJvcmAgb3V0cHV0XG4gIC8vIHRoYXQgc2hvd3MgdGhlIHR5cGUgKFN5bWJvbCwgVGVtcG9yYWwuUGxhaW5EYXRlLCBldGMuKSB0aGF0IGNhdXNlZCB0aGVcbiAgLy8gcHJvYmxlbSBhbmQgaG93IHRoYXQgdHlwZSB3YXMgdXNlZDoga2V5LCBhdHJyaWJ1dGUsIGlucHV0IHZhbHVlIHByb3AsIGV0Yy5cbiAgLy8gSW4gbW9zdCBjYXNlcywgdGhpcyBjb25zb2xlIG91dHB1dCBhbHNvIHNob3dzIHRoZSBjb21wb25lbnQgYW5kIGl0c1xuICAvLyBhbmNlc3RvciBjb21wb25lbnRzIHdoZXJlIHRoZSBleGNlcHRpb24gaGFwcGVuZWQuXG4gIC8vXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSByZWFjdC1pbnRlcm5hbC9zYWZlLXN0cmluZy1jb2VyY2lvblxuICByZXR1cm4gJycgKyB2YWx1ZTtcbn1cbmZ1bmN0aW9uIGNoZWNrS2V5U3RyaW5nQ29lcmNpb24odmFsdWUpIHtcbiAge1xuICAgIGlmICh3aWxsQ29lcmNpb25UaHJvdyh2YWx1ZSkpIHtcbiAgICAgIGVycm9yKCdUaGUgcHJvdmlkZWQga2V5IGlzIGFuIHVuc3VwcG9ydGVkIHR5cGUgJXMuJyArICcgVGhpcyB2YWx1ZSBtdXN0IGJlIGNvZXJjZWQgdG8gYSBzdHJpbmcgYmVmb3JlIGJlZm9yZSB1c2luZyBpdCBoZXJlLicsIHR5cGVOYW1lKHZhbHVlKSk7XG5cbiAgICAgIHJldHVybiB0ZXN0U3RyaW5nQ29lcmNpb24odmFsdWUpOyAvLyB0aHJvdyAodG8gaGVscCBjYWxsZXJzIGZpbmQgdHJvdWJsZXNob290aW5nIGNvbW1lbnRzKVxuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiBnZXRXcmFwcGVkTmFtZShvdXRlclR5cGUsIGlubmVyVHlwZSwgd3JhcHBlck5hbWUpIHtcbiAgdmFyIGRpc3BsYXlOYW1lID0gb3V0ZXJUeXBlLmRpc3BsYXlOYW1lO1xuXG4gIGlmIChkaXNwbGF5TmFtZSkge1xuICAgIHJldHVybiBkaXNwbGF5TmFtZTtcbiAgfVxuXG4gIHZhciBmdW5jdGlvbk5hbWUgPSBpbm5lclR5cGUuZGlzcGxheU5hbWUgfHwgaW5uZXJUeXBlLm5hbWUgfHwgJyc7XG4gIHJldHVybiBmdW5jdGlvbk5hbWUgIT09ICcnID8gd3JhcHBlck5hbWUgKyBcIihcIiArIGZ1bmN0aW9uTmFtZSArIFwiKVwiIDogd3JhcHBlck5hbWU7XG59IC8vIEtlZXAgaW4gc3luYyB3aXRoIHJlYWN0LXJlY29uY2lsZXIvZ2V0Q29tcG9uZW50TmFtZUZyb21GaWJlclxuXG5cbmZ1bmN0aW9uIGdldENvbnRleHROYW1lKHR5cGUpIHtcbiAgcmV0dXJuIHR5cGUuZGlzcGxheU5hbWUgfHwgJ0NvbnRleHQnO1xufSAvLyBOb3RlIHRoYXQgdGhlIHJlY29uY2lsZXIgcGFja2FnZSBzaG91bGQgZ2VuZXJhbGx5IHByZWZlciB0byB1c2UgZ2V0Q29tcG9uZW50TmFtZUZyb21GaWJlcigpIGluc3RlYWQuXG5cblxuZnVuY3Rpb24gZ2V0Q29tcG9uZW50TmFtZUZyb21UeXBlKHR5cGUpIHtcbiAgaWYgKHR5cGUgPT0gbnVsbCkge1xuICAgIC8vIEhvc3Qgcm9vdCwgdGV4dCBub2RlIG9yIGp1c3QgaW52YWxpZCB0eXBlLlxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAge1xuICAgIGlmICh0eXBlb2YgdHlwZS50YWcgPT09ICdudW1iZXInKSB7XG4gICAgICBlcnJvcignUmVjZWl2ZWQgYW4gdW5leHBlY3RlZCBvYmplY3QgaW4gZ2V0Q29tcG9uZW50TmFtZUZyb21UeXBlKCkuICcgKyAnVGhpcyBpcyBsaWtlbHkgYSBidWcgaW4gUmVhY3QuIFBsZWFzZSBmaWxlIGFuIGlzc3VlLicpO1xuICAgIH1cbiAgfVxuXG4gIGlmICh0eXBlb2YgdHlwZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHJldHVybiB0eXBlLmRpc3BsYXlOYW1lIHx8IHR5cGUubmFtZSB8fCBudWxsO1xuICB9XG5cbiAgaWYgKHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJykge1xuICAgIHJldHVybiB0eXBlO1xuICB9XG5cbiAgc3dpdGNoICh0eXBlKSB7XG4gICAgY2FzZSBSRUFDVF9GUkFHTUVOVF9UWVBFOlxuICAgICAgcmV0dXJuICdGcmFnbWVudCc7XG5cbiAgICBjYXNlIFJFQUNUX1BPUlRBTF9UWVBFOlxuICAgICAgcmV0dXJuICdQb3J0YWwnO1xuXG4gICAgY2FzZSBSRUFDVF9QUk9GSUxFUl9UWVBFOlxuICAgICAgcmV0dXJuICdQcm9maWxlcic7XG5cbiAgICBjYXNlIFJFQUNUX1NUUklDVF9NT0RFX1RZUEU6XG4gICAgICByZXR1cm4gJ1N0cmljdE1vZGUnO1xuXG4gICAgY2FzZSBSRUFDVF9TVVNQRU5TRV9UWVBFOlxuICAgICAgcmV0dXJuICdTdXNwZW5zZSc7XG5cbiAgICBjYXNlIFJFQUNUX1NVU1BFTlNFX0xJU1RfVFlQRTpcbiAgICAgIHJldHVybiAnU3VzcGVuc2VMaXN0JztcblxuICB9XG5cbiAgaWYgKHR5cGVvZiB0eXBlID09PSAnb2JqZWN0Jykge1xuICAgIHN3aXRjaCAodHlwZS4kJHR5cGVvZikge1xuICAgICAgY2FzZSBSRUFDVF9DT05URVhUX1RZUEU6XG4gICAgICAgIHZhciBjb250ZXh0ID0gdHlwZTtcbiAgICAgICAgcmV0dXJuIGdldENvbnRleHROYW1lKGNvbnRleHQpICsgJy5Db25zdW1lcic7XG5cbiAgICAgIGNhc2UgUkVBQ1RfUFJPVklERVJfVFlQRTpcbiAgICAgICAgdmFyIHByb3ZpZGVyID0gdHlwZTtcbiAgICAgICAgcmV0dXJuIGdldENvbnRleHROYW1lKHByb3ZpZGVyLl9jb250ZXh0KSArICcuUHJvdmlkZXInO1xuXG4gICAgICBjYXNlIFJFQUNUX0ZPUldBUkRfUkVGX1RZUEU6XG4gICAgICAgIHJldHVybiBnZXRXcmFwcGVkTmFtZSh0eXBlLCB0eXBlLnJlbmRlciwgJ0ZvcndhcmRSZWYnKTtcblxuICAgICAgY2FzZSBSRUFDVF9NRU1PX1RZUEU6XG4gICAgICAgIHZhciBvdXRlck5hbWUgPSB0eXBlLmRpc3BsYXlOYW1lIHx8IG51bGw7XG5cbiAgICAgICAgaWYgKG91dGVyTmFtZSAhPT0gbnVsbCkge1xuICAgICAgICAgIHJldHVybiBvdXRlck5hbWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZ2V0Q29tcG9uZW50TmFtZUZyb21UeXBlKHR5cGUudHlwZSkgfHwgJ01lbW8nO1xuXG4gICAgICBjYXNlIFJFQUNUX0xBWllfVFlQRTpcbiAgICAgICAge1xuICAgICAgICAgIHZhciBsYXp5Q29tcG9uZW50ID0gdHlwZTtcbiAgICAgICAgICB2YXIgcGF5bG9hZCA9IGxhenlDb21wb25lbnQuX3BheWxvYWQ7XG4gICAgICAgICAgdmFyIGluaXQgPSBsYXp5Q29tcG9uZW50Ll9pbml0O1xuXG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBnZXRDb21wb25lbnROYW1lRnJvbVR5cGUoaW5pdChwYXlsb2FkKSk7XG4gICAgICAgICAgfSBjYXRjaCAoeCkge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1mYWxsdGhyb3VnaFxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBudWxsO1xufVxuXG52YXIgaGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuXG52YXIgUkVTRVJWRURfUFJPUFMgPSB7XG4gIGtleTogdHJ1ZSxcbiAgcmVmOiB0cnVlLFxuICBfX3NlbGY6IHRydWUsXG4gIF9fc291cmNlOiB0cnVlXG59O1xudmFyIHNwZWNpYWxQcm9wS2V5V2FybmluZ1Nob3duLCBzcGVjaWFsUHJvcFJlZldhcm5pbmdTaG93biwgZGlkV2FybkFib3V0U3RyaW5nUmVmcztcblxue1xuICBkaWRXYXJuQWJvdXRTdHJpbmdSZWZzID0ge307XG59XG5cbmZ1bmN0aW9uIGhhc1ZhbGlkUmVmKGNvbmZpZykge1xuICB7XG4gICAgaWYgKGhhc093blByb3BlcnR5LmNhbGwoY29uZmlnLCAncmVmJykpIHtcbiAgICAgIHZhciBnZXR0ZXIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKGNvbmZpZywgJ3JlZicpLmdldDtcblxuICAgICAgaWYgKGdldHRlciAmJiBnZXR0ZXIuaXNSZWFjdFdhcm5pbmcpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBjb25maWcucmVmICE9PSB1bmRlZmluZWQ7XG59XG5cbmZ1bmN0aW9uIGhhc1ZhbGlkS2V5KGNvbmZpZykge1xuICB7XG4gICAgaWYgKGhhc093blByb3BlcnR5LmNhbGwoY29uZmlnLCAna2V5JykpIHtcbiAgICAgIHZhciBnZXR0ZXIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKGNvbmZpZywgJ2tleScpLmdldDtcblxuICAgICAgaWYgKGdldHRlciAmJiBnZXR0ZXIuaXNSZWFjdFdhcm5pbmcpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBjb25maWcua2V5ICE9PSB1bmRlZmluZWQ7XG59XG5cbmZ1bmN0aW9uIGRlZmluZUtleVByb3BXYXJuaW5nR2V0dGVyKHByb3BzLCBkaXNwbGF5TmFtZSkge1xuICB2YXIgd2FybkFib3V0QWNjZXNzaW5nS2V5ID0gZnVuY3Rpb24gKCkge1xuICAgIHtcbiAgICAgIGlmICghc3BlY2lhbFByb3BLZXlXYXJuaW5nU2hvd24pIHtcbiAgICAgICAgc3BlY2lhbFByb3BLZXlXYXJuaW5nU2hvd24gPSB0cnVlO1xuXG4gICAgICAgIGVycm9yKCclczogYGtleWAgaXMgbm90IGEgcHJvcC4gVHJ5aW5nIHRvIGFjY2VzcyBpdCB3aWxsIHJlc3VsdCAnICsgJ2luIGB1bmRlZmluZWRgIGJlaW5nIHJldHVybmVkLiBJZiB5b3UgbmVlZCB0byBhY2Nlc3MgdGhlIHNhbWUgJyArICd2YWx1ZSB3aXRoaW4gdGhlIGNoaWxkIGNvbXBvbmVudCwgeW91IHNob3VsZCBwYXNzIGl0IGFzIGEgZGlmZmVyZW50ICcgKyAncHJvcC4gKGh0dHBzOi8vcmVhY3Rqcy5vcmcvbGluay9zcGVjaWFsLXByb3BzKScsIGRpc3BsYXlOYW1lKTtcbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgd2FybkFib3V0QWNjZXNzaW5nS2V5LmlzUmVhY3RXYXJuaW5nID0gdHJ1ZTtcbiAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHByb3BzLCAna2V5Jywge1xuICAgIGdldDogd2FybkFib3V0QWNjZXNzaW5nS2V5LFxuICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICB9KTtcbn1cblxuZnVuY3Rpb24gZGVmaW5lUmVmUHJvcFdhcm5pbmdHZXR0ZXIocHJvcHMsIGRpc3BsYXlOYW1lKSB7XG4gIHZhciB3YXJuQWJvdXRBY2Nlc3NpbmdSZWYgPSBmdW5jdGlvbiAoKSB7XG4gICAge1xuICAgICAgaWYgKCFzcGVjaWFsUHJvcFJlZldhcm5pbmdTaG93bikge1xuICAgICAgICBzcGVjaWFsUHJvcFJlZldhcm5pbmdTaG93biA9IHRydWU7XG5cbiAgICAgICAgZXJyb3IoJyVzOiBgcmVmYCBpcyBub3QgYSBwcm9wLiBUcnlpbmcgdG8gYWNjZXNzIGl0IHdpbGwgcmVzdWx0ICcgKyAnaW4gYHVuZGVmaW5lZGAgYmVpbmcgcmV0dXJuZWQuIElmIHlvdSBuZWVkIHRvIGFjY2VzcyB0aGUgc2FtZSAnICsgJ3ZhbHVlIHdpdGhpbiB0aGUgY2hpbGQgY29tcG9uZW50LCB5b3Ugc2hvdWxkIHBhc3MgaXQgYXMgYSBkaWZmZXJlbnQgJyArICdwcm9wLiAoaHR0cHM6Ly9yZWFjdGpzLm9yZy9saW5rL3NwZWNpYWwtcHJvcHMpJywgZGlzcGxheU5hbWUpO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICB3YXJuQWJvdXRBY2Nlc3NpbmdSZWYuaXNSZWFjdFdhcm5pbmcgPSB0cnVlO1xuICBPYmplY3QuZGVmaW5lUHJvcGVydHkocHJvcHMsICdyZWYnLCB7XG4gICAgZ2V0OiB3YXJuQWJvdXRBY2Nlc3NpbmdSZWYsXG4gICAgY29uZmlndXJhYmxlOiB0cnVlXG4gIH0pO1xufVxuXG5mdW5jdGlvbiB3YXJuSWZTdHJpbmdSZWZDYW5ub3RCZUF1dG9Db252ZXJ0ZWQoY29uZmlnKSB7XG4gIHtcbiAgICBpZiAodHlwZW9mIGNvbmZpZy5yZWYgPT09ICdzdHJpbmcnICYmIFJlYWN0Q3VycmVudE93bmVyLmN1cnJlbnQgJiYgY29uZmlnLl9fc2VsZiAmJiBSZWFjdEN1cnJlbnRPd25lci5jdXJyZW50LnN0YXRlTm9kZSAhPT0gY29uZmlnLl9fc2VsZikge1xuICAgICAgdmFyIGNvbXBvbmVudE5hbWUgPSBnZXRDb21wb25lbnROYW1lRnJvbVR5cGUoUmVhY3RDdXJyZW50T3duZXIuY3VycmVudC50eXBlKTtcblxuICAgICAgaWYgKCFkaWRXYXJuQWJvdXRTdHJpbmdSZWZzW2NvbXBvbmVudE5hbWVdKSB7XG4gICAgICAgIGVycm9yKCdDb21wb25lbnQgXCIlc1wiIGNvbnRhaW5zIHRoZSBzdHJpbmcgcmVmIFwiJXNcIi4gJyArICdTdXBwb3J0IGZvciBzdHJpbmcgcmVmcyB3aWxsIGJlIHJlbW92ZWQgaW4gYSBmdXR1cmUgbWFqb3IgcmVsZWFzZS4gJyArICdUaGlzIGNhc2UgY2Fubm90IGJlIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIHRvIGFuIGFycm93IGZ1bmN0aW9uLiAnICsgJ1dlIGFzayB5b3UgdG8gbWFudWFsbHkgZml4IHRoaXMgY2FzZSBieSB1c2luZyB1c2VSZWYoKSBvciBjcmVhdGVSZWYoKSBpbnN0ZWFkLiAnICsgJ0xlYXJuIG1vcmUgYWJvdXQgdXNpbmcgcmVmcyBzYWZlbHkgaGVyZTogJyArICdodHRwczovL3JlYWN0anMub3JnL2xpbmsvc3RyaWN0LW1vZGUtc3RyaW5nLXJlZicsIGNvbXBvbmVudE5hbWUsIGNvbmZpZy5yZWYpO1xuXG4gICAgICAgIGRpZFdhcm5BYm91dFN0cmluZ1JlZnNbY29tcG9uZW50TmFtZV0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxufVxuLyoqXG4gKiBGYWN0b3J5IG1ldGhvZCB0byBjcmVhdGUgYSBuZXcgUmVhY3QgZWxlbWVudC4gVGhpcyBubyBsb25nZXIgYWRoZXJlcyB0b1xuICogdGhlIGNsYXNzIHBhdHRlcm4sIHNvIGRvIG5vdCB1c2UgbmV3IHRvIGNhbGwgaXQuIEFsc28sIGluc3RhbmNlb2YgY2hlY2tcbiAqIHdpbGwgbm90IHdvcmsuIEluc3RlYWQgdGVzdCAkJHR5cGVvZiBmaWVsZCBhZ2FpbnN0IFN5bWJvbC5mb3IoJ3JlYWN0LmVsZW1lbnQnKSB0byBjaGVja1xuICogaWYgc29tZXRoaW5nIGlzIGEgUmVhY3QgRWxlbWVudC5cbiAqXG4gKiBAcGFyYW0geyp9IHR5cGVcbiAqIEBwYXJhbSB7Kn0gcHJvcHNcbiAqIEBwYXJhbSB7Kn0ga2V5XG4gKiBAcGFyYW0ge3N0cmluZ3xvYmplY3R9IHJlZlxuICogQHBhcmFtIHsqfSBvd25lclxuICogQHBhcmFtIHsqfSBzZWxmIEEgKnRlbXBvcmFyeSogaGVscGVyIHRvIGRldGVjdCBwbGFjZXMgd2hlcmUgYHRoaXNgIGlzXG4gKiBkaWZmZXJlbnQgZnJvbSB0aGUgYG93bmVyYCB3aGVuIFJlYWN0LmNyZWF0ZUVsZW1lbnQgaXMgY2FsbGVkLCBzbyB0aGF0IHdlXG4gKiBjYW4gd2Fybi4gV2Ugd2FudCB0byBnZXQgcmlkIG9mIG93bmVyIGFuZCByZXBsYWNlIHN0cmluZyBgcmVmYHMgd2l0aCBhcnJvd1xuICogZnVuY3Rpb25zLCBhbmQgYXMgbG9uZyBhcyBgdGhpc2AgYW5kIG93bmVyIGFyZSB0aGUgc2FtZSwgdGhlcmUgd2lsbCBiZSBub1xuICogY2hhbmdlIGluIGJlaGF2aW9yLlxuICogQHBhcmFtIHsqfSBzb3VyY2UgQW4gYW5ub3RhdGlvbiBvYmplY3QgKGFkZGVkIGJ5IGEgdHJhbnNwaWxlciBvciBvdGhlcndpc2UpXG4gKiBpbmRpY2F0aW5nIGZpbGVuYW1lLCBsaW5lIG51bWJlciwgYW5kL29yIG90aGVyIGluZm9ybWF0aW9uLlxuICogQGludGVybmFsXG4gKi9cblxuXG52YXIgUmVhY3RFbGVtZW50ID0gZnVuY3Rpb24gKHR5cGUsIGtleSwgcmVmLCBzZWxmLCBzb3VyY2UsIG93bmVyLCBwcm9wcykge1xuICB2YXIgZWxlbWVudCA9IHtcbiAgICAvLyBUaGlzIHRhZyBhbGxvd3MgdXMgdG8gdW5pcXVlbHkgaWRlbnRpZnkgdGhpcyBhcyBhIFJlYWN0IEVsZW1lbnRcbiAgICAkJHR5cGVvZjogUkVBQ1RfRUxFTUVOVF9UWVBFLFxuICAgIC8vIEJ1aWx0LWluIHByb3BlcnRpZXMgdGhhdCBiZWxvbmcgb24gdGhlIGVsZW1lbnRcbiAgICB0eXBlOiB0eXBlLFxuICAgIGtleToga2V5LFxuICAgIHJlZjogcmVmLFxuICAgIHByb3BzOiBwcm9wcyxcbiAgICAvLyBSZWNvcmQgdGhlIGNvbXBvbmVudCByZXNwb25zaWJsZSBmb3IgY3JlYXRpbmcgdGhpcyBlbGVtZW50LlxuICAgIF9vd25lcjogb3duZXJcbiAgfTtcblxuICB7XG4gICAgLy8gVGhlIHZhbGlkYXRpb24gZmxhZyBpcyBjdXJyZW50bHkgbXV0YXRpdmUuIFdlIHB1dCBpdCBvblxuICAgIC8vIGFuIGV4dGVybmFsIGJhY2tpbmcgc3RvcmUgc28gdGhhdCB3ZSBjYW4gZnJlZXplIHRoZSB3aG9sZSBvYmplY3QuXG4gICAgLy8gVGhpcyBjYW4gYmUgcmVwbGFjZWQgd2l0aCBhIFdlYWtNYXAgb25jZSB0aGV5IGFyZSBpbXBsZW1lbnRlZCBpblxuICAgIC8vIGNvbW1vbmx5IHVzZWQgZGV2ZWxvcG1lbnQgZW52aXJvbm1lbnRzLlxuICAgIGVsZW1lbnQuX3N0b3JlID0ge307IC8vIFRvIG1ha2UgY29tcGFyaW5nIFJlYWN0RWxlbWVudHMgZWFzaWVyIGZvciB0ZXN0aW5nIHB1cnBvc2VzLCB3ZSBtYWtlXG4gICAgLy8gdGhlIHZhbGlkYXRpb24gZmxhZyBub24tZW51bWVyYWJsZSAod2hlcmUgcG9zc2libGUsIHdoaWNoIHNob3VsZFxuICAgIC8vIGluY2x1ZGUgZXZlcnkgZW52aXJvbm1lbnQgd2UgcnVuIHRlc3RzIGluKSwgc28gdGhlIHRlc3QgZnJhbWV3b3JrXG4gICAgLy8gaWdub3JlcyBpdC5cblxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShlbGVtZW50Ll9zdG9yZSwgJ3ZhbGlkYXRlZCcsIHtcbiAgICAgIGNvbmZpZ3VyYWJsZTogZmFsc2UsXG4gICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgIHdyaXRhYmxlOiB0cnVlLFxuICAgICAgdmFsdWU6IGZhbHNlXG4gICAgfSk7IC8vIHNlbGYgYW5kIHNvdXJjZSBhcmUgREVWIG9ubHkgcHJvcGVydGllcy5cblxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShlbGVtZW50LCAnX3NlbGYnLCB7XG4gICAgICBjb25maWd1cmFibGU6IGZhbHNlLFxuICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICB3cml0YWJsZTogZmFsc2UsXG4gICAgICB2YWx1ZTogc2VsZlxuICAgIH0pOyAvLyBUd28gZWxlbWVudHMgY3JlYXRlZCBpbiB0d28gZGlmZmVyZW50IHBsYWNlcyBzaG91bGQgYmUgY29uc2lkZXJlZFxuICAgIC8vIGVxdWFsIGZvciB0ZXN0aW5nIHB1cnBvc2VzIGFuZCB0aGVyZWZvcmUgd2UgaGlkZSBpdCBmcm9tIGVudW1lcmF0aW9uLlxuXG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGVsZW1lbnQsICdfc291cmNlJywge1xuICAgICAgY29uZmlndXJhYmxlOiBmYWxzZSxcbiAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgd3JpdGFibGU6IGZhbHNlLFxuICAgICAgdmFsdWU6IHNvdXJjZVxuICAgIH0pO1xuXG4gICAgaWYgKE9iamVjdC5mcmVlemUpIHtcbiAgICAgIE9iamVjdC5mcmVlemUoZWxlbWVudC5wcm9wcyk7XG4gICAgICBPYmplY3QuZnJlZXplKGVsZW1lbnQpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBlbGVtZW50O1xufTtcbi8qKlxuICogQ3JlYXRlIGFuZCByZXR1cm4gYSBuZXcgUmVhY3RFbGVtZW50IG9mIHRoZSBnaXZlbiB0eXBlLlxuICogU2VlIGh0dHBzOi8vcmVhY3Rqcy5vcmcvZG9jcy9yZWFjdC1hcGkuaHRtbCNjcmVhdGVlbGVtZW50XG4gKi9cblxuZnVuY3Rpb24gY3JlYXRlRWxlbWVudCh0eXBlLCBjb25maWcsIGNoaWxkcmVuKSB7XG4gIHZhciBwcm9wTmFtZTsgLy8gUmVzZXJ2ZWQgbmFtZXMgYXJlIGV4dHJhY3RlZFxuXG4gIHZhciBwcm9wcyA9IHt9O1xuICB2YXIga2V5ID0gbnVsbDtcbiAgdmFyIHJlZiA9IG51bGw7XG4gIHZhciBzZWxmID0gbnVsbDtcbiAgdmFyIHNvdXJjZSA9IG51bGw7XG5cbiAgaWYgKGNvbmZpZyAhPSBudWxsKSB7XG4gICAgaWYgKGhhc1ZhbGlkUmVmKGNvbmZpZykpIHtcbiAgICAgIHJlZiA9IGNvbmZpZy5yZWY7XG5cbiAgICAgIHtcbiAgICAgICAgd2FybklmU3RyaW5nUmVmQ2Fubm90QmVBdXRvQ29udmVydGVkKGNvbmZpZyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGhhc1ZhbGlkS2V5KGNvbmZpZykpIHtcbiAgICAgIHtcbiAgICAgICAgY2hlY2tLZXlTdHJpbmdDb2VyY2lvbihjb25maWcua2V5KTtcbiAgICAgIH1cblxuICAgICAga2V5ID0gJycgKyBjb25maWcua2V5O1xuICAgIH1cblxuICAgIHNlbGYgPSBjb25maWcuX19zZWxmID09PSB1bmRlZmluZWQgPyBudWxsIDogY29uZmlnLl9fc2VsZjtcbiAgICBzb3VyY2UgPSBjb25maWcuX19zb3VyY2UgPT09IHVuZGVmaW5lZCA/IG51bGwgOiBjb25maWcuX19zb3VyY2U7IC8vIFJlbWFpbmluZyBwcm9wZXJ0aWVzIGFyZSBhZGRlZCB0byBhIG5ldyBwcm9wcyBvYmplY3RcblxuICAgIGZvciAocHJvcE5hbWUgaW4gY29uZmlnKSB7XG4gICAgICBpZiAoaGFzT3duUHJvcGVydHkuY2FsbChjb25maWcsIHByb3BOYW1lKSAmJiAhUkVTRVJWRURfUFJPUFMuaGFzT3duUHJvcGVydHkocHJvcE5hbWUpKSB7XG4gICAgICAgIHByb3BzW3Byb3BOYW1lXSA9IGNvbmZpZ1twcm9wTmFtZV07XG4gICAgICB9XG4gICAgfVxuICB9IC8vIENoaWxkcmVuIGNhbiBiZSBtb3JlIHRoYW4gb25lIGFyZ3VtZW50LCBhbmQgdGhvc2UgYXJlIHRyYW5zZmVycmVkIG9udG9cbiAgLy8gdGhlIG5ld2x5IGFsbG9jYXRlZCBwcm9wcyBvYmplY3QuXG5cblxuICB2YXIgY2hpbGRyZW5MZW5ndGggPSBhcmd1bWVudHMubGVuZ3RoIC0gMjtcblxuICBpZiAoY2hpbGRyZW5MZW5ndGggPT09IDEpIHtcbiAgICBwcm9wcy5jaGlsZHJlbiA9IGNoaWxkcmVuO1xuICB9IGVsc2UgaWYgKGNoaWxkcmVuTGVuZ3RoID4gMSkge1xuICAgIHZhciBjaGlsZEFycmF5ID0gQXJyYXkoY2hpbGRyZW5MZW5ndGgpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBjaGlsZHJlbkxlbmd0aDsgaSsrKSB7XG4gICAgICBjaGlsZEFycmF5W2ldID0gYXJndW1lbnRzW2kgKyAyXTtcbiAgICB9XG5cbiAgICB7XG4gICAgICBpZiAoT2JqZWN0LmZyZWV6ZSkge1xuICAgICAgICBPYmplY3QuZnJlZXplKGNoaWxkQXJyYXkpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHByb3BzLmNoaWxkcmVuID0gY2hpbGRBcnJheTtcbiAgfSAvLyBSZXNvbHZlIGRlZmF1bHQgcHJvcHNcblxuXG4gIGlmICh0eXBlICYmIHR5cGUuZGVmYXVsdFByb3BzKSB7XG4gICAgdmFyIGRlZmF1bHRQcm9wcyA9IHR5cGUuZGVmYXVsdFByb3BzO1xuXG4gICAgZm9yIChwcm9wTmFtZSBpbiBkZWZhdWx0UHJvcHMpIHtcbiAgICAgIGlmIChwcm9wc1twcm9wTmFtZV0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICBwcm9wc1twcm9wTmFtZV0gPSBkZWZhdWx0UHJvcHNbcHJvcE5hbWVdO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHtcbiAgICBpZiAoa2V5IHx8IHJlZikge1xuICAgICAgdmFyIGRpc3BsYXlOYW1lID0gdHlwZW9mIHR5cGUgPT09ICdmdW5jdGlvbicgPyB0eXBlLmRpc3BsYXlOYW1lIHx8IHR5cGUubmFtZSB8fCAnVW5rbm93bicgOiB0eXBlO1xuXG4gICAgICBpZiAoa2V5KSB7XG4gICAgICAgIGRlZmluZUtleVByb3BXYXJuaW5nR2V0dGVyKHByb3BzLCBkaXNwbGF5TmFtZSk7XG4gICAgICB9XG5cbiAgICAgIGlmIChyZWYpIHtcbiAgICAgICAgZGVmaW5lUmVmUHJvcFdhcm5pbmdHZXR0ZXIocHJvcHMsIGRpc3BsYXlOYW1lKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gUmVhY3RFbGVtZW50KHR5cGUsIGtleSwgcmVmLCBzZWxmLCBzb3VyY2UsIFJlYWN0Q3VycmVudE93bmVyLmN1cnJlbnQsIHByb3BzKTtcbn1cbmZ1bmN0aW9uIGNsb25lQW5kUmVwbGFjZUtleShvbGRFbGVtZW50LCBuZXdLZXkpIHtcbiAgdmFyIG5ld0VsZW1lbnQgPSBSZWFjdEVsZW1lbnQob2xkRWxlbWVudC50eXBlLCBuZXdLZXksIG9sZEVsZW1lbnQucmVmLCBvbGRFbGVtZW50Ll9zZWxmLCBvbGRFbGVtZW50Ll9zb3VyY2UsIG9sZEVsZW1lbnQuX293bmVyLCBvbGRFbGVtZW50LnByb3BzKTtcbiAgcmV0dXJuIG5ld0VsZW1lbnQ7XG59XG4vKipcbiAqIENsb25lIGFuZCByZXR1cm4gYSBuZXcgUmVhY3RFbGVtZW50IHVzaW5nIGVsZW1lbnQgYXMgdGhlIHN0YXJ0aW5nIHBvaW50LlxuICogU2VlIGh0dHBzOi8vcmVhY3Rqcy5vcmcvZG9jcy9yZWFjdC1hcGkuaHRtbCNjbG9uZWVsZW1lbnRcbiAqL1xuXG5mdW5jdGlvbiBjbG9uZUVsZW1lbnQoZWxlbWVudCwgY29uZmlnLCBjaGlsZHJlbikge1xuICBpZiAoZWxlbWVudCA9PT0gbnVsbCB8fCBlbGVtZW50ID09PSB1bmRlZmluZWQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJSZWFjdC5jbG9uZUVsZW1lbnQoLi4uKTogVGhlIGFyZ3VtZW50IG11c3QgYmUgYSBSZWFjdCBlbGVtZW50LCBidXQgeW91IHBhc3NlZCBcIiArIGVsZW1lbnQgKyBcIi5cIik7XG4gIH1cblxuICB2YXIgcHJvcE5hbWU7IC8vIE9yaWdpbmFsIHByb3BzIGFyZSBjb3BpZWRcblxuICB2YXIgcHJvcHMgPSBhc3NpZ24oe30sIGVsZW1lbnQucHJvcHMpOyAvLyBSZXNlcnZlZCBuYW1lcyBhcmUgZXh0cmFjdGVkXG5cbiAgdmFyIGtleSA9IGVsZW1lbnQua2V5O1xuICB2YXIgcmVmID0gZWxlbWVudC5yZWY7IC8vIFNlbGYgaXMgcHJlc2VydmVkIHNpbmNlIHRoZSBvd25lciBpcyBwcmVzZXJ2ZWQuXG5cbiAgdmFyIHNlbGYgPSBlbGVtZW50Ll9zZWxmOyAvLyBTb3VyY2UgaXMgcHJlc2VydmVkIHNpbmNlIGNsb25lRWxlbWVudCBpcyB1bmxpa2VseSB0byBiZSB0YXJnZXRlZCBieSBhXG4gIC8vIHRyYW5zcGlsZXIsIGFuZCB0aGUgb3JpZ2luYWwgc291cmNlIGlzIHByb2JhYmx5IGEgYmV0dGVyIGluZGljYXRvciBvZiB0aGVcbiAgLy8gdHJ1ZSBvd25lci5cblxuICB2YXIgc291cmNlID0gZWxlbWVudC5fc291cmNlOyAvLyBPd25lciB3aWxsIGJlIHByZXNlcnZlZCwgdW5sZXNzIHJlZiBpcyBvdmVycmlkZGVuXG5cbiAgdmFyIG93bmVyID0gZWxlbWVudC5fb3duZXI7XG5cbiAgaWYgKGNvbmZpZyAhPSBudWxsKSB7XG4gICAgaWYgKGhhc1ZhbGlkUmVmKGNvbmZpZykpIHtcbiAgICAgIC8vIFNpbGVudGx5IHN0ZWFsIHRoZSByZWYgZnJvbSB0aGUgcGFyZW50LlxuICAgICAgcmVmID0gY29uZmlnLnJlZjtcbiAgICAgIG93bmVyID0gUmVhY3RDdXJyZW50T3duZXIuY3VycmVudDtcbiAgICB9XG5cbiAgICBpZiAoaGFzVmFsaWRLZXkoY29uZmlnKSkge1xuICAgICAge1xuICAgICAgICBjaGVja0tleVN0cmluZ0NvZXJjaW9uKGNvbmZpZy5rZXkpO1xuICAgICAgfVxuXG4gICAgICBrZXkgPSAnJyArIGNvbmZpZy5rZXk7XG4gICAgfSAvLyBSZW1haW5pbmcgcHJvcGVydGllcyBvdmVycmlkZSBleGlzdGluZyBwcm9wc1xuXG5cbiAgICB2YXIgZGVmYXVsdFByb3BzO1xuXG4gICAgaWYgKGVsZW1lbnQudHlwZSAmJiBlbGVtZW50LnR5cGUuZGVmYXVsdFByb3BzKSB7XG4gICAgICBkZWZhdWx0UHJvcHMgPSBlbGVtZW50LnR5cGUuZGVmYXVsdFByb3BzO1xuICAgIH1cblxuICAgIGZvciAocHJvcE5hbWUgaW4gY29uZmlnKSB7XG4gICAgICBpZiAoaGFzT3duUHJvcGVydHkuY2FsbChjb25maWcsIHByb3BOYW1lKSAmJiAhUkVTRVJWRURfUFJPUFMuaGFzT3duUHJvcGVydHkocHJvcE5hbWUpKSB7XG4gICAgICAgIGlmIChjb25maWdbcHJvcE5hbWVdID09PSB1bmRlZmluZWQgJiYgZGVmYXVsdFByb3BzICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAvLyBSZXNvbHZlIGRlZmF1bHQgcHJvcHNcbiAgICAgICAgICBwcm9wc1twcm9wTmFtZV0gPSBkZWZhdWx0UHJvcHNbcHJvcE5hbWVdO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHByb3BzW3Byb3BOYW1lXSA9IGNvbmZpZ1twcm9wTmFtZV07XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH0gLy8gQ2hpbGRyZW4gY2FuIGJlIG1vcmUgdGhhbiBvbmUgYXJndW1lbnQsIGFuZCB0aG9zZSBhcmUgdHJhbnNmZXJyZWQgb250b1xuICAvLyB0aGUgbmV3bHkgYWxsb2NhdGVkIHByb3BzIG9iamVjdC5cblxuXG4gIHZhciBjaGlsZHJlbkxlbmd0aCA9IGFyZ3VtZW50cy5sZW5ndGggLSAyO1xuXG4gIGlmIChjaGlsZHJlbkxlbmd0aCA9PT0gMSkge1xuICAgIHByb3BzLmNoaWxkcmVuID0gY2hpbGRyZW47XG4gIH0gZWxzZSBpZiAoY2hpbGRyZW5MZW5ndGggPiAxKSB7XG4gICAgdmFyIGNoaWxkQXJyYXkgPSBBcnJheShjaGlsZHJlbkxlbmd0aCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGNoaWxkcmVuTGVuZ3RoOyBpKyspIHtcbiAgICAgIGNoaWxkQXJyYXlbaV0gPSBhcmd1bWVudHNbaSArIDJdO1xuICAgIH1cblxuICAgIHByb3BzLmNoaWxkcmVuID0gY2hpbGRBcnJheTtcbiAgfVxuXG4gIHJldHVybiBSZWFjdEVsZW1lbnQoZWxlbWVudC50eXBlLCBrZXksIHJlZiwgc2VsZiwgc291cmNlLCBvd25lciwgcHJvcHMpO1xufVxuLyoqXG4gKiBWZXJpZmllcyB0aGUgb2JqZWN0IGlzIGEgUmVhY3RFbGVtZW50LlxuICogU2VlIGh0dHBzOi8vcmVhY3Rqcy5vcmcvZG9jcy9yZWFjdC1hcGkuaHRtbCNpc3ZhbGlkZWxlbWVudFxuICogQHBhcmFtIHs/b2JqZWN0fSBvYmplY3RcbiAqIEByZXR1cm4ge2Jvb2xlYW59IFRydWUgaWYgYG9iamVjdGAgaXMgYSBSZWFjdEVsZW1lbnQuXG4gKiBAZmluYWxcbiAqL1xuXG5mdW5jdGlvbiBpc1ZhbGlkRWxlbWVudChvYmplY3QpIHtcbiAgcmV0dXJuIHR5cGVvZiBvYmplY3QgPT09ICdvYmplY3QnICYmIG9iamVjdCAhPT0gbnVsbCAmJiBvYmplY3QuJCR0eXBlb2YgPT09IFJFQUNUX0VMRU1FTlRfVFlQRTtcbn1cblxudmFyIFNFUEFSQVRPUiA9ICcuJztcbnZhciBTVUJTRVBBUkFUT1IgPSAnOic7XG4vKipcbiAqIEVzY2FwZSBhbmQgd3JhcCBrZXkgc28gaXQgaXMgc2FmZSB0byB1c2UgYXMgYSByZWFjdGlkXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IGtleSB0byBiZSBlc2NhcGVkLlxuICogQHJldHVybiB7c3RyaW5nfSB0aGUgZXNjYXBlZCBrZXkuXG4gKi9cblxuZnVuY3Rpb24gZXNjYXBlKGtleSkge1xuICB2YXIgZXNjYXBlUmVnZXggPSAvWz06XS9nO1xuICB2YXIgZXNjYXBlckxvb2t1cCA9IHtcbiAgICAnPSc6ICc9MCcsXG4gICAgJzonOiAnPTInXG4gIH07XG4gIHZhciBlc2NhcGVkU3RyaW5nID0ga2V5LnJlcGxhY2UoZXNjYXBlUmVnZXgsIGZ1bmN0aW9uIChtYXRjaCkge1xuICAgIHJldHVybiBlc2NhcGVyTG9va3VwW21hdGNoXTtcbiAgfSk7XG4gIHJldHVybiAnJCcgKyBlc2NhcGVkU3RyaW5nO1xufVxuLyoqXG4gKiBUT0RPOiBUZXN0IHRoYXQgYSBzaW5nbGUgY2hpbGQgYW5kIGFuIGFycmF5IHdpdGggb25lIGl0ZW0gaGF2ZSB0aGUgc2FtZSBrZXlcbiAqIHBhdHRlcm4uXG4gKi9cblxuXG52YXIgZGlkV2FybkFib3V0TWFwcyA9IGZhbHNlO1xudmFyIHVzZXJQcm92aWRlZEtleUVzY2FwZVJlZ2V4ID0gL1xcLysvZztcblxuZnVuY3Rpb24gZXNjYXBlVXNlclByb3ZpZGVkS2V5KHRleHQpIHtcbiAgcmV0dXJuIHRleHQucmVwbGFjZSh1c2VyUHJvdmlkZWRLZXlFc2NhcGVSZWdleCwgJyQmLycpO1xufVxuLyoqXG4gKiBHZW5lcmF0ZSBhIGtleSBzdHJpbmcgdGhhdCBpZGVudGlmaWVzIGEgZWxlbWVudCB3aXRoaW4gYSBzZXQuXG4gKlxuICogQHBhcmFtIHsqfSBlbGVtZW50IEEgZWxlbWVudCB0aGF0IGNvdWxkIGNvbnRhaW4gYSBtYW51YWwga2V5LlxuICogQHBhcmFtIHtudW1iZXJ9IGluZGV4IEluZGV4IHRoYXQgaXMgdXNlZCBpZiBhIG1hbnVhbCBrZXkgaXMgbm90IHByb3ZpZGVkLlxuICogQHJldHVybiB7c3RyaW5nfVxuICovXG5cblxuZnVuY3Rpb24gZ2V0RWxlbWVudEtleShlbGVtZW50LCBpbmRleCkge1xuICAvLyBEbyBzb21lIHR5cGVjaGVja2luZyBoZXJlIHNpbmNlIHdlIGNhbGwgdGhpcyBibGluZGx5LiBXZSB3YW50IHRvIGVuc3VyZVxuICAvLyB0aGF0IHdlIGRvbid0IGJsb2NrIHBvdGVudGlhbCBmdXR1cmUgRVMgQVBJcy5cbiAgaWYgKHR5cGVvZiBlbGVtZW50ID09PSAnb2JqZWN0JyAmJiBlbGVtZW50ICE9PSBudWxsICYmIGVsZW1lbnQua2V5ICE9IG51bGwpIHtcbiAgICAvLyBFeHBsaWNpdCBrZXlcbiAgICB7XG4gICAgICBjaGVja0tleVN0cmluZ0NvZXJjaW9uKGVsZW1lbnQua2V5KTtcbiAgICB9XG5cbiAgICByZXR1cm4gZXNjYXBlKCcnICsgZWxlbWVudC5rZXkpO1xuICB9IC8vIEltcGxpY2l0IGtleSBkZXRlcm1pbmVkIGJ5IHRoZSBpbmRleCBpbiB0aGUgc2V0XG5cblxuICByZXR1cm4gaW5kZXgudG9TdHJpbmcoMzYpO1xufVxuXG5mdW5jdGlvbiBtYXBJbnRvQXJyYXkoY2hpbGRyZW4sIGFycmF5LCBlc2NhcGVkUHJlZml4LCBuYW1lU29GYXIsIGNhbGxiYWNrKSB7XG4gIHZhciB0eXBlID0gdHlwZW9mIGNoaWxkcmVuO1xuXG4gIGlmICh0eXBlID09PSAndW5kZWZpbmVkJyB8fCB0eXBlID09PSAnYm9vbGVhbicpIHtcbiAgICAvLyBBbGwgb2YgdGhlIGFib3ZlIGFyZSBwZXJjZWl2ZWQgYXMgbnVsbC5cbiAgICBjaGlsZHJlbiA9IG51bGw7XG4gIH1cblxuICB2YXIgaW52b2tlQ2FsbGJhY2sgPSBmYWxzZTtcblxuICBpZiAoY2hpbGRyZW4gPT09IG51bGwpIHtcbiAgICBpbnZva2VDYWxsYmFjayA9IHRydWU7XG4gIH0gZWxzZSB7XG4gICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICBjYXNlICdzdHJpbmcnOlxuICAgICAgY2FzZSAnbnVtYmVyJzpcbiAgICAgICAgaW52b2tlQ2FsbGJhY2sgPSB0cnVlO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSAnb2JqZWN0JzpcbiAgICAgICAgc3dpdGNoIChjaGlsZHJlbi4kJHR5cGVvZikge1xuICAgICAgICAgIGNhc2UgUkVBQ1RfRUxFTUVOVF9UWVBFOlxuICAgICAgICAgIGNhc2UgUkVBQ1RfUE9SVEFMX1RZUEU6XG4gICAgICAgICAgICBpbnZva2VDYWxsYmFjayA9IHRydWU7XG4gICAgICAgIH1cblxuICAgIH1cbiAgfVxuXG4gIGlmIChpbnZva2VDYWxsYmFjaykge1xuICAgIHZhciBfY2hpbGQgPSBjaGlsZHJlbjtcbiAgICB2YXIgbWFwcGVkQ2hpbGQgPSBjYWxsYmFjayhfY2hpbGQpOyAvLyBJZiBpdCdzIHRoZSBvbmx5IGNoaWxkLCB0cmVhdCB0aGUgbmFtZSBhcyBpZiBpdCB3YXMgd3JhcHBlZCBpbiBhbiBhcnJheVxuICAgIC8vIHNvIHRoYXQgaXQncyBjb25zaXN0ZW50IGlmIHRoZSBudW1iZXIgb2YgY2hpbGRyZW4gZ3Jvd3M6XG5cbiAgICB2YXIgY2hpbGRLZXkgPSBuYW1lU29GYXIgPT09ICcnID8gU0VQQVJBVE9SICsgZ2V0RWxlbWVudEtleShfY2hpbGQsIDApIDogbmFtZVNvRmFyO1xuXG4gICAgaWYgKGlzQXJyYXkobWFwcGVkQ2hpbGQpKSB7XG4gICAgICB2YXIgZXNjYXBlZENoaWxkS2V5ID0gJyc7XG5cbiAgICAgIGlmIChjaGlsZEtleSAhPSBudWxsKSB7XG4gICAgICAgIGVzY2FwZWRDaGlsZEtleSA9IGVzY2FwZVVzZXJQcm92aWRlZEtleShjaGlsZEtleSkgKyAnLyc7XG4gICAgICB9XG5cbiAgICAgIG1hcEludG9BcnJheShtYXBwZWRDaGlsZCwgYXJyYXksIGVzY2FwZWRDaGlsZEtleSwgJycsIGZ1bmN0aW9uIChjKSB7XG4gICAgICAgIHJldHVybiBjO1xuICAgICAgfSk7XG4gICAgfSBlbHNlIGlmIChtYXBwZWRDaGlsZCAhPSBudWxsKSB7XG4gICAgICBpZiAoaXNWYWxpZEVsZW1lbnQobWFwcGVkQ2hpbGQpKSB7XG4gICAgICAgIHtcbiAgICAgICAgICAvLyBUaGUgYGlmYCBzdGF0ZW1lbnQgaGVyZSBwcmV2ZW50cyBhdXRvLWRpc2FibGluZyBvZiB0aGUgc2FmZVxuICAgICAgICAgIC8vIGNvZXJjaW9uIEVTTGludCBydWxlLCBzbyB3ZSBtdXN0IG1hbnVhbGx5IGRpc2FibGUgaXQgYmVsb3cuXG4gICAgICAgICAgLy8gJEZsb3dGaXhNZSBGbG93IGluY29ycmVjdGx5IHRoaW5rcyBSZWFjdC5Qb3J0YWwgZG9lc24ndCBoYXZlIGEga2V5XG4gICAgICAgICAgaWYgKG1hcHBlZENoaWxkLmtleSAmJiAoIV9jaGlsZCB8fCBfY2hpbGQua2V5ICE9PSBtYXBwZWRDaGlsZC5rZXkpKSB7XG4gICAgICAgICAgICBjaGVja0tleVN0cmluZ0NvZXJjaW9uKG1hcHBlZENoaWxkLmtleSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgbWFwcGVkQ2hpbGQgPSBjbG9uZUFuZFJlcGxhY2VLZXkobWFwcGVkQ2hpbGQsIC8vIEtlZXAgYm90aCB0aGUgKG1hcHBlZCkgYW5kIG9sZCBrZXlzIGlmIHRoZXkgZGlmZmVyLCBqdXN0IGFzXG4gICAgICAgIC8vIHRyYXZlcnNlQWxsQ2hpbGRyZW4gdXNlZCB0byBkbyBmb3Igb2JqZWN0cyBhcyBjaGlsZHJlblxuICAgICAgICBlc2NhcGVkUHJlZml4ICsgKCAvLyAkRmxvd0ZpeE1lIEZsb3cgaW5jb3JyZWN0bHkgdGhpbmtzIFJlYWN0LlBvcnRhbCBkb2Vzbid0IGhhdmUgYSBrZXlcbiAgICAgICAgbWFwcGVkQ2hpbGQua2V5ICYmICghX2NoaWxkIHx8IF9jaGlsZC5rZXkgIT09IG1hcHBlZENoaWxkLmtleSkgPyAvLyAkRmxvd0ZpeE1lIEZsb3cgaW5jb3JyZWN0bHkgdGhpbmtzIGV4aXN0aW5nIGVsZW1lbnQncyBrZXkgY2FuIGJlIGEgbnVtYmVyXG4gICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSByZWFjdC1pbnRlcm5hbC9zYWZlLXN0cmluZy1jb2VyY2lvblxuICAgICAgICBlc2NhcGVVc2VyUHJvdmlkZWRLZXkoJycgKyBtYXBwZWRDaGlsZC5rZXkpICsgJy8nIDogJycpICsgY2hpbGRLZXkpO1xuICAgICAgfVxuXG4gICAgICBhcnJheS5wdXNoKG1hcHBlZENoaWxkKTtcbiAgICB9XG5cbiAgICByZXR1cm4gMTtcbiAgfVxuXG4gIHZhciBjaGlsZDtcbiAgdmFyIG5leHROYW1lO1xuICB2YXIgc3VidHJlZUNvdW50ID0gMDsgLy8gQ291bnQgb2YgY2hpbGRyZW4gZm91bmQgaW4gdGhlIGN1cnJlbnQgc3VidHJlZS5cblxuICB2YXIgbmV4dE5hbWVQcmVmaXggPSBuYW1lU29GYXIgPT09ICcnID8gU0VQQVJBVE9SIDogbmFtZVNvRmFyICsgU1VCU0VQQVJBVE9SO1xuXG4gIGlmIChpc0FycmF5KGNoaWxkcmVuKSkge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgY2hpbGRyZW4ubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNoaWxkID0gY2hpbGRyZW5baV07XG4gICAgICBuZXh0TmFtZSA9IG5leHROYW1lUHJlZml4ICsgZ2V0RWxlbWVudEtleShjaGlsZCwgaSk7XG4gICAgICBzdWJ0cmVlQ291bnQgKz0gbWFwSW50b0FycmF5KGNoaWxkLCBhcnJheSwgZXNjYXBlZFByZWZpeCwgbmV4dE5hbWUsIGNhbGxiYWNrKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgdmFyIGl0ZXJhdG9yRm4gPSBnZXRJdGVyYXRvckZuKGNoaWxkcmVuKTtcblxuICAgIGlmICh0eXBlb2YgaXRlcmF0b3JGbiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgdmFyIGl0ZXJhYmxlQ2hpbGRyZW4gPSBjaGlsZHJlbjtcblxuICAgICAge1xuICAgICAgICAvLyBXYXJuIGFib3V0IHVzaW5nIE1hcHMgYXMgY2hpbGRyZW5cbiAgICAgICAgaWYgKGl0ZXJhdG9yRm4gPT09IGl0ZXJhYmxlQ2hpbGRyZW4uZW50cmllcykge1xuICAgICAgICAgIGlmICghZGlkV2FybkFib3V0TWFwcykge1xuICAgICAgICAgICAgd2FybignVXNpbmcgTWFwcyBhcyBjaGlsZHJlbiBpcyBub3Qgc3VwcG9ydGVkLiAnICsgJ1VzZSBhbiBhcnJheSBvZiBrZXllZCBSZWFjdEVsZW1lbnRzIGluc3RlYWQuJyk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZGlkV2FybkFib3V0TWFwcyA9IHRydWU7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgdmFyIGl0ZXJhdG9yID0gaXRlcmF0b3JGbi5jYWxsKGl0ZXJhYmxlQ2hpbGRyZW4pO1xuICAgICAgdmFyIHN0ZXA7XG4gICAgICB2YXIgaWkgPSAwO1xuXG4gICAgICB3aGlsZSAoIShzdGVwID0gaXRlcmF0b3IubmV4dCgpKS5kb25lKSB7XG4gICAgICAgIGNoaWxkID0gc3RlcC52YWx1ZTtcbiAgICAgICAgbmV4dE5hbWUgPSBuZXh0TmFtZVByZWZpeCArIGdldEVsZW1lbnRLZXkoY2hpbGQsIGlpKyspO1xuICAgICAgICBzdWJ0cmVlQ291bnQgKz0gbWFwSW50b0FycmF5KGNoaWxkLCBhcnJheSwgZXNjYXBlZFByZWZpeCwgbmV4dE5hbWUsIGNhbGxiYWNrKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHR5cGUgPT09ICdvYmplY3QnKSB7XG4gICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgcmVhY3QtaW50ZXJuYWwvc2FmZS1zdHJpbmctY29lcmNpb25cbiAgICAgIHZhciBjaGlsZHJlblN0cmluZyA9IFN0cmluZyhjaGlsZHJlbik7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJPYmplY3RzIGFyZSBub3QgdmFsaWQgYXMgYSBSZWFjdCBjaGlsZCAoZm91bmQ6IFwiICsgKGNoaWxkcmVuU3RyaW5nID09PSAnW29iamVjdCBPYmplY3RdJyA/ICdvYmplY3Qgd2l0aCBrZXlzIHsnICsgT2JqZWN0LmtleXMoY2hpbGRyZW4pLmpvaW4oJywgJykgKyAnfScgOiBjaGlsZHJlblN0cmluZykgKyBcIikuIFwiICsgJ0lmIHlvdSBtZWFudCB0byByZW5kZXIgYSBjb2xsZWN0aW9uIG9mIGNoaWxkcmVuLCB1c2UgYW4gYXJyYXkgJyArICdpbnN0ZWFkLicpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBzdWJ0cmVlQ291bnQ7XG59XG5cbi8qKlxuICogTWFwcyBjaGlsZHJlbiB0aGF0IGFyZSB0eXBpY2FsbHkgc3BlY2lmaWVkIGFzIGBwcm9wcy5jaGlsZHJlbmAuXG4gKlxuICogU2VlIGh0dHBzOi8vcmVhY3Rqcy5vcmcvZG9jcy9yZWFjdC1hcGkuaHRtbCNyZWFjdGNoaWxkcmVubWFwXG4gKlxuICogVGhlIHByb3ZpZGVkIG1hcEZ1bmN0aW9uKGNoaWxkLCBpbmRleCkgd2lsbCBiZSBjYWxsZWQgZm9yIGVhY2hcbiAqIGxlYWYgY2hpbGQuXG4gKlxuICogQHBhcmFtIHs/Kn0gY2hpbGRyZW4gQ2hpbGRyZW4gdHJlZSBjb250YWluZXIuXG4gKiBAcGFyYW0ge2Z1bmN0aW9uKCosIGludCl9IGZ1bmMgVGhlIG1hcCBmdW5jdGlvbi5cbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBDb250ZXh0IGZvciBtYXBGdW5jdGlvbi5cbiAqIEByZXR1cm4ge29iamVjdH0gT2JqZWN0IGNvbnRhaW5pbmcgdGhlIG9yZGVyZWQgbWFwIG9mIHJlc3VsdHMuXG4gKi9cbmZ1bmN0aW9uIG1hcENoaWxkcmVuKGNoaWxkcmVuLCBmdW5jLCBjb250ZXh0KSB7XG4gIGlmIChjaGlsZHJlbiA9PSBudWxsKSB7XG4gICAgcmV0dXJuIGNoaWxkcmVuO1xuICB9XG5cbiAgdmFyIHJlc3VsdCA9IFtdO1xuICB2YXIgY291bnQgPSAwO1xuICBtYXBJbnRvQXJyYXkoY2hpbGRyZW4sIHJlc3VsdCwgJycsICcnLCBmdW5jdGlvbiAoY2hpbGQpIHtcbiAgICByZXR1cm4gZnVuYy5jYWxsKGNvbnRleHQsIGNoaWxkLCBjb3VudCsrKTtcbiAgfSk7XG4gIHJldHVybiByZXN1bHQ7XG59XG4vKipcbiAqIENvdW50IHRoZSBudW1iZXIgb2YgY2hpbGRyZW4gdGhhdCBhcmUgdHlwaWNhbGx5IHNwZWNpZmllZCBhc1xuICogYHByb3BzLmNoaWxkcmVuYC5cbiAqXG4gKiBTZWUgaHR0cHM6Ly9yZWFjdGpzLm9yZy9kb2NzL3JlYWN0LWFwaS5odG1sI3JlYWN0Y2hpbGRyZW5jb3VudFxuICpcbiAqIEBwYXJhbSB7Pyp9IGNoaWxkcmVuIENoaWxkcmVuIHRyZWUgY29udGFpbmVyLlxuICogQHJldHVybiB7bnVtYmVyfSBUaGUgbnVtYmVyIG9mIGNoaWxkcmVuLlxuICovXG5cblxuZnVuY3Rpb24gY291bnRDaGlsZHJlbihjaGlsZHJlbikge1xuICB2YXIgbiA9IDA7XG4gIG1hcENoaWxkcmVuKGNoaWxkcmVuLCBmdW5jdGlvbiAoKSB7XG4gICAgbisrOyAvLyBEb24ndCByZXR1cm4gYW55dGhpbmdcbiAgfSk7XG4gIHJldHVybiBuO1xufVxuXG4vKipcbiAqIEl0ZXJhdGVzIHRocm91Z2ggY2hpbGRyZW4gdGhhdCBhcmUgdHlwaWNhbGx5IHNwZWNpZmllZCBhcyBgcHJvcHMuY2hpbGRyZW5gLlxuICpcbiAqIFNlZSBodHRwczovL3JlYWN0anMub3JnL2RvY3MvcmVhY3QtYXBpLmh0bWwjcmVhY3RjaGlsZHJlbmZvcmVhY2hcbiAqXG4gKiBUaGUgcHJvdmlkZWQgZm9yRWFjaEZ1bmMoY2hpbGQsIGluZGV4KSB3aWxsIGJlIGNhbGxlZCBmb3IgZWFjaFxuICogbGVhZiBjaGlsZC5cbiAqXG4gKiBAcGFyYW0gez8qfSBjaGlsZHJlbiBDaGlsZHJlbiB0cmVlIGNvbnRhaW5lci5cbiAqIEBwYXJhbSB7ZnVuY3Rpb24oKiwgaW50KX0gZm9yRWFjaEZ1bmNcbiAqIEBwYXJhbSB7Kn0gZm9yRWFjaENvbnRleHQgQ29udGV4dCBmb3IgZm9yRWFjaENvbnRleHQuXG4gKi9cbmZ1bmN0aW9uIGZvckVhY2hDaGlsZHJlbihjaGlsZHJlbiwgZm9yRWFjaEZ1bmMsIGZvckVhY2hDb250ZXh0KSB7XG4gIG1hcENoaWxkcmVuKGNoaWxkcmVuLCBmdW5jdGlvbiAoKSB7XG4gICAgZm9yRWFjaEZ1bmMuYXBwbHkodGhpcywgYXJndW1lbnRzKTsgLy8gRG9uJ3QgcmV0dXJuIGFueXRoaW5nLlxuICB9LCBmb3JFYWNoQ29udGV4dCk7XG59XG4vKipcbiAqIEZsYXR0ZW4gYSBjaGlsZHJlbiBvYmplY3QgKHR5cGljYWxseSBzcGVjaWZpZWQgYXMgYHByb3BzLmNoaWxkcmVuYCkgYW5kXG4gKiByZXR1cm4gYW4gYXJyYXkgd2l0aCBhcHByb3ByaWF0ZWx5IHJlLWtleWVkIGNoaWxkcmVuLlxuICpcbiAqIFNlZSBodHRwczovL3JlYWN0anMub3JnL2RvY3MvcmVhY3QtYXBpLmh0bWwjcmVhY3RjaGlsZHJlbnRvYXJyYXlcbiAqL1xuXG5cbmZ1bmN0aW9uIHRvQXJyYXkoY2hpbGRyZW4pIHtcbiAgcmV0dXJuIG1hcENoaWxkcmVuKGNoaWxkcmVuLCBmdW5jdGlvbiAoY2hpbGQpIHtcbiAgICByZXR1cm4gY2hpbGQ7XG4gIH0pIHx8IFtdO1xufVxuLyoqXG4gKiBSZXR1cm5zIHRoZSBmaXJzdCBjaGlsZCBpbiBhIGNvbGxlY3Rpb24gb2YgY2hpbGRyZW4gYW5kIHZlcmlmaWVzIHRoYXQgdGhlcmVcbiAqIGlzIG9ubHkgb25lIGNoaWxkIGluIHRoZSBjb2xsZWN0aW9uLlxuICpcbiAqIFNlZSBodHRwczovL3JlYWN0anMub3JnL2RvY3MvcmVhY3QtYXBpLmh0bWwjcmVhY3RjaGlsZHJlbm9ubHlcbiAqXG4gKiBUaGUgY3VycmVudCBpbXBsZW1lbnRhdGlvbiBvZiB0aGlzIGZ1bmN0aW9uIGFzc3VtZXMgdGhhdCBhIHNpbmdsZSBjaGlsZCBnZXRzXG4gKiBwYXNzZWQgd2l0aG91dCBhIHdyYXBwZXIsIGJ1dCB0aGUgcHVycG9zZSBvZiB0aGlzIGhlbHBlciBmdW5jdGlvbiBpcyB0b1xuICogYWJzdHJhY3QgYXdheSB0aGUgcGFydGljdWxhciBzdHJ1Y3R1cmUgb2YgY2hpbGRyZW4uXG4gKlxuICogQHBhcmFtIHs/b2JqZWN0fSBjaGlsZHJlbiBDaGlsZCBjb2xsZWN0aW9uIHN0cnVjdHVyZS5cbiAqIEByZXR1cm4ge1JlYWN0RWxlbWVudH0gVGhlIGZpcnN0IGFuZCBvbmx5IGBSZWFjdEVsZW1lbnRgIGNvbnRhaW5lZCBpbiB0aGVcbiAqIHN0cnVjdHVyZS5cbiAqL1xuXG5cbmZ1bmN0aW9uIG9ubHlDaGlsZChjaGlsZHJlbikge1xuICBpZiAoIWlzVmFsaWRFbGVtZW50KGNoaWxkcmVuKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignUmVhY3QuQ2hpbGRyZW4ub25seSBleHBlY3RlZCB0byByZWNlaXZlIGEgc2luZ2xlIFJlYWN0IGVsZW1lbnQgY2hpbGQuJyk7XG4gIH1cblxuICByZXR1cm4gY2hpbGRyZW47XG59XG5cbmZ1bmN0aW9uIGNyZWF0ZUNvbnRleHQoZGVmYXVsdFZhbHVlKSB7XG4gIC8vIFRPRE86IFNlY29uZCBhcmd1bWVudCB1c2VkIHRvIGJlIGFuIG9wdGlvbmFsIGBjYWxjdWxhdGVDaGFuZ2VkQml0c2BcbiAgLy8gZnVuY3Rpb24uIFdhcm4gdG8gcmVzZXJ2ZSBmb3IgZnV0dXJlIHVzZT9cbiAgdmFyIGNvbnRleHQgPSB7XG4gICAgJCR0eXBlb2Y6IFJFQUNUX0NPTlRFWFRfVFlQRSxcbiAgICAvLyBBcyBhIHdvcmthcm91bmQgdG8gc3VwcG9ydCBtdWx0aXBsZSBjb25jdXJyZW50IHJlbmRlcmVycywgd2UgY2F0ZWdvcml6ZVxuICAgIC8vIHNvbWUgcmVuZGVyZXJzIGFzIHByaW1hcnkgYW5kIG90aGVycyBhcyBzZWNvbmRhcnkuIFdlIG9ubHkgZXhwZWN0XG4gICAgLy8gdGhlcmUgdG8gYmUgdHdvIGNvbmN1cnJlbnQgcmVuZGVyZXJzIGF0IG1vc3Q6IFJlYWN0IE5hdGl2ZSAocHJpbWFyeSkgYW5kXG4gICAgLy8gRmFicmljIChzZWNvbmRhcnkpOyBSZWFjdCBET00gKHByaW1hcnkpIGFuZCBSZWFjdCBBUlQgKHNlY29uZGFyeSkuXG4gICAgLy8gU2Vjb25kYXJ5IHJlbmRlcmVycyBzdG9yZSB0aGVpciBjb250ZXh0IHZhbHVlcyBvbiBzZXBhcmF0ZSBmaWVsZHMuXG4gICAgX2N1cnJlbnRWYWx1ZTogZGVmYXVsdFZhbHVlLFxuICAgIF9jdXJyZW50VmFsdWUyOiBkZWZhdWx0VmFsdWUsXG4gICAgLy8gVXNlZCB0byB0cmFjayBob3cgbWFueSBjb25jdXJyZW50IHJlbmRlcmVycyB0aGlzIGNvbnRleHQgY3VycmVudGx5XG4gICAgLy8gc3VwcG9ydHMgd2l0aGluIGluIGEgc2luZ2xlIHJlbmRlcmVyLiBTdWNoIGFzIHBhcmFsbGVsIHNlcnZlciByZW5kZXJpbmcuXG4gICAgX3RocmVhZENvdW50OiAwLFxuICAgIC8vIFRoZXNlIGFyZSBjaXJjdWxhclxuICAgIFByb3ZpZGVyOiBudWxsLFxuICAgIENvbnN1bWVyOiBudWxsLFxuICAgIC8vIEFkZCB0aGVzZSB0byB1c2Ugc2FtZSBoaWRkZW4gY2xhc3MgaW4gVk0gYXMgU2VydmVyQ29udGV4dFxuICAgIF9kZWZhdWx0VmFsdWU6IG51bGwsXG4gICAgX2dsb2JhbE5hbWU6IG51bGxcbiAgfTtcbiAgY29udGV4dC5Qcm92aWRlciA9IHtcbiAgICAkJHR5cGVvZjogUkVBQ1RfUFJPVklERVJfVFlQRSxcbiAgICBfY29udGV4dDogY29udGV4dFxuICB9O1xuICB2YXIgaGFzV2FybmVkQWJvdXRVc2luZ05lc3RlZENvbnRleHRDb25zdW1lcnMgPSBmYWxzZTtcbiAgdmFyIGhhc1dhcm5lZEFib3V0VXNpbmdDb25zdW1lclByb3ZpZGVyID0gZmFsc2U7XG4gIHZhciBoYXNXYXJuZWRBYm91dERpc3BsYXlOYW1lT25Db25zdW1lciA9IGZhbHNlO1xuXG4gIHtcbiAgICAvLyBBIHNlcGFyYXRlIG9iamVjdCwgYnV0IHByb3hpZXMgYmFjayB0byB0aGUgb3JpZ2luYWwgY29udGV4dCBvYmplY3QgZm9yXG4gICAgLy8gYmFja3dhcmRzIGNvbXBhdGliaWxpdHkuIEl0IGhhcyBhIGRpZmZlcmVudCAkJHR5cGVvZiwgc28gd2UgY2FuIHByb3Blcmx5XG4gICAgLy8gd2FybiBmb3IgdGhlIGluY29ycmVjdCB1c2FnZSBvZiBDb250ZXh0IGFzIGEgQ29uc3VtZXIuXG4gICAgdmFyIENvbnN1bWVyID0ge1xuICAgICAgJCR0eXBlb2Y6IFJFQUNUX0NPTlRFWFRfVFlQRSxcbiAgICAgIF9jb250ZXh0OiBjb250ZXh0XG4gICAgfTsgLy8gJEZsb3dGaXhNZTogRmxvdyBjb21wbGFpbnMgYWJvdXQgbm90IHNldHRpbmcgYSB2YWx1ZSwgd2hpY2ggaXMgaW50ZW50aW9uYWwgaGVyZVxuXG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnRpZXMoQ29uc3VtZXIsIHtcbiAgICAgIFByb3ZpZGVyOiB7XG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmICghaGFzV2FybmVkQWJvdXRVc2luZ0NvbnN1bWVyUHJvdmlkZXIpIHtcbiAgICAgICAgICAgIGhhc1dhcm5lZEFib3V0VXNpbmdDb25zdW1lclByb3ZpZGVyID0gdHJ1ZTtcblxuICAgICAgICAgICAgZXJyb3IoJ1JlbmRlcmluZyA8Q29udGV4dC5Db25zdW1lci5Qcm92aWRlcj4gaXMgbm90IHN1cHBvcnRlZCBhbmQgd2lsbCBiZSByZW1vdmVkIGluICcgKyAnYSBmdXR1cmUgbWFqb3IgcmVsZWFzZS4gRGlkIHlvdSBtZWFuIHRvIHJlbmRlciA8Q29udGV4dC5Qcm92aWRlcj4gaW5zdGVhZD8nKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29udGV4dC5Qcm92aWRlcjtcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAoX1Byb3ZpZGVyKSB7XG4gICAgICAgICAgY29udGV4dC5Qcm92aWRlciA9IF9Qcm92aWRlcjtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIF9jdXJyZW50VmFsdWU6IHtcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuIGNvbnRleHQuX2N1cnJlbnRWYWx1ZTtcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAoX2N1cnJlbnRWYWx1ZSkge1xuICAgICAgICAgIGNvbnRleHQuX2N1cnJlbnRWYWx1ZSA9IF9jdXJyZW50VmFsdWU7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBfY3VycmVudFZhbHVlMjoge1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICByZXR1cm4gY29udGV4dC5fY3VycmVudFZhbHVlMjtcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAoX2N1cnJlbnRWYWx1ZTIpIHtcbiAgICAgICAgICBjb250ZXh0Ll9jdXJyZW50VmFsdWUyID0gX2N1cnJlbnRWYWx1ZTI7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBfdGhyZWFkQ291bnQ6IHtcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuIGNvbnRleHQuX3RocmVhZENvdW50O1xuICAgICAgICB9LFxuICAgICAgICBzZXQ6IGZ1bmN0aW9uIChfdGhyZWFkQ291bnQpIHtcbiAgICAgICAgICBjb250ZXh0Ll90aHJlYWRDb3VudCA9IF90aHJlYWRDb3VudDtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIENvbnN1bWVyOiB7XG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmICghaGFzV2FybmVkQWJvdXRVc2luZ05lc3RlZENvbnRleHRDb25zdW1lcnMpIHtcbiAgICAgICAgICAgIGhhc1dhcm5lZEFib3V0VXNpbmdOZXN0ZWRDb250ZXh0Q29uc3VtZXJzID0gdHJ1ZTtcblxuICAgICAgICAgICAgZXJyb3IoJ1JlbmRlcmluZyA8Q29udGV4dC5Db25zdW1lci5Db25zdW1lcj4gaXMgbm90IHN1cHBvcnRlZCBhbmQgd2lsbCBiZSByZW1vdmVkIGluICcgKyAnYSBmdXR1cmUgbWFqb3IgcmVsZWFzZS4gRGlkIHlvdSBtZWFuIHRvIHJlbmRlciA8Q29udGV4dC5Db25zdW1lcj4gaW5zdGVhZD8nKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29udGV4dC5Db25zdW1lcjtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGRpc3BsYXlOYW1lOiB7XG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiBjb250ZXh0LmRpc3BsYXlOYW1lO1xuICAgICAgICB9LFxuICAgICAgICBzZXQ6IGZ1bmN0aW9uIChkaXNwbGF5TmFtZSkge1xuICAgICAgICAgIGlmICghaGFzV2FybmVkQWJvdXREaXNwbGF5TmFtZU9uQ29uc3VtZXIpIHtcbiAgICAgICAgICAgIHdhcm4oJ1NldHRpbmcgYGRpc3BsYXlOYW1lYCBvbiBDb250ZXh0LkNvbnN1bWVyIGhhcyBubyBlZmZlY3QuICcgKyBcIllvdSBzaG91bGQgc2V0IGl0IGRpcmVjdGx5IG9uIHRoZSBjb250ZXh0IHdpdGggQ29udGV4dC5kaXNwbGF5TmFtZSA9ICclcycuXCIsIGRpc3BsYXlOYW1lKTtcblxuICAgICAgICAgICAgaGFzV2FybmVkQWJvdXREaXNwbGF5TmFtZU9uQ29uc3VtZXIgPSB0cnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pOyAvLyAkRmxvd0ZpeE1lOiBGbG93IGNvbXBsYWlucyBhYm91dCBtaXNzaW5nIHByb3BlcnRpZXMgYmVjYXVzZSBpdCBkb2Vzbid0IHVuZGVyc3RhbmQgZGVmaW5lUHJvcGVydHlcblxuICAgIGNvbnRleHQuQ29uc3VtZXIgPSBDb25zdW1lcjtcbiAgfVxuXG4gIHtcbiAgICBjb250ZXh0Ll9jdXJyZW50UmVuZGVyZXIgPSBudWxsO1xuICAgIGNvbnRleHQuX2N1cnJlbnRSZW5kZXJlcjIgPSBudWxsO1xuICB9XG5cbiAgcmV0dXJuIGNvbnRleHQ7XG59XG5cbnZhciBVbmluaXRpYWxpemVkID0gLTE7XG52YXIgUGVuZGluZyA9IDA7XG52YXIgUmVzb2x2ZWQgPSAxO1xudmFyIFJlamVjdGVkID0gMjtcblxuZnVuY3Rpb24gbGF6eUluaXRpYWxpemVyKHBheWxvYWQpIHtcbiAgaWYgKHBheWxvYWQuX3N0YXR1cyA9PT0gVW5pbml0aWFsaXplZCkge1xuICAgIHZhciBjdG9yID0gcGF5bG9hZC5fcmVzdWx0O1xuICAgIHZhciB0aGVuYWJsZSA9IGN0b3IoKTsgLy8gVHJhbnNpdGlvbiB0byB0aGUgbmV4dCBzdGF0ZS5cbiAgICAvLyBUaGlzIG1pZ2h0IHRocm93IGVpdGhlciBiZWNhdXNlIGl0J3MgbWlzc2luZyBvciB0aHJvd3MuIElmIHNvLCB3ZSB0cmVhdCBpdFxuICAgIC8vIGFzIHN0aWxsIHVuaW5pdGlhbGl6ZWQgYW5kIHRyeSBhZ2FpbiBuZXh0IHRpbWUuIFdoaWNoIGlzIHRoZSBzYW1lIGFzIHdoYXRcbiAgICAvLyBoYXBwZW5zIGlmIHRoZSBjdG9yIG9yIGFueSB3cmFwcGVycyBwcm9jZXNzaW5nIHRoZSBjdG9yIHRocm93cy4gVGhpcyBtaWdodFxuICAgIC8vIGVuZCB1cCBmaXhpbmcgaXQgaWYgdGhlIHJlc29sdXRpb24gd2FzIGEgY29uY3VycmVuY3kgYnVnLlxuXG4gICAgdGhlbmFibGUudGhlbihmdW5jdGlvbiAobW9kdWxlT2JqZWN0KSB7XG4gICAgICBpZiAocGF5bG9hZC5fc3RhdHVzID09PSBQZW5kaW5nIHx8IHBheWxvYWQuX3N0YXR1cyA9PT0gVW5pbml0aWFsaXplZCkge1xuICAgICAgICAvLyBUcmFuc2l0aW9uIHRvIHRoZSBuZXh0IHN0YXRlLlxuICAgICAgICB2YXIgcmVzb2x2ZWQgPSBwYXlsb2FkO1xuICAgICAgICByZXNvbHZlZC5fc3RhdHVzID0gUmVzb2x2ZWQ7XG4gICAgICAgIHJlc29sdmVkLl9yZXN1bHQgPSBtb2R1bGVPYmplY3Q7XG4gICAgICB9XG4gICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICBpZiAocGF5bG9hZC5fc3RhdHVzID09PSBQZW5kaW5nIHx8IHBheWxvYWQuX3N0YXR1cyA9PT0gVW5pbml0aWFsaXplZCkge1xuICAgICAgICAvLyBUcmFuc2l0aW9uIHRvIHRoZSBuZXh0IHN0YXRlLlxuICAgICAgICB2YXIgcmVqZWN0ZWQgPSBwYXlsb2FkO1xuICAgICAgICByZWplY3RlZC5fc3RhdHVzID0gUmVqZWN0ZWQ7XG4gICAgICAgIHJlamVjdGVkLl9yZXN1bHQgPSBlcnJvcjtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGlmIChwYXlsb2FkLl9zdGF0dXMgPT09IFVuaW5pdGlhbGl6ZWQpIHtcbiAgICAgIC8vIEluIGNhc2UsIHdlJ3JlIHN0aWxsIHVuaW5pdGlhbGl6ZWQsIHRoZW4gd2UncmUgd2FpdGluZyBmb3IgdGhlIHRoZW5hYmxlXG4gICAgICAvLyB0byByZXNvbHZlLiBTZXQgaXQgYXMgcGVuZGluZyBpbiB0aGUgbWVhbnRpbWUuXG4gICAgICB2YXIgcGVuZGluZyA9IHBheWxvYWQ7XG4gICAgICBwZW5kaW5nLl9zdGF0dXMgPSBQZW5kaW5nO1xuICAgICAgcGVuZGluZy5fcmVzdWx0ID0gdGhlbmFibGU7XG4gICAgfVxuICB9XG5cbiAgaWYgKHBheWxvYWQuX3N0YXR1cyA9PT0gUmVzb2x2ZWQpIHtcbiAgICB2YXIgbW9kdWxlT2JqZWN0ID0gcGF5bG9hZC5fcmVzdWx0O1xuXG4gICAge1xuICAgICAgaWYgKG1vZHVsZU9iamVjdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGVycm9yKCdsYXp5OiBFeHBlY3RlZCB0aGUgcmVzdWx0IG9mIGEgZHluYW1pYyBpbXAnICsgJ29ydCgpIGNhbGwuICcgKyAnSW5zdGVhZCByZWNlaXZlZDogJXNcXG5cXG5Zb3VyIGNvZGUgc2hvdWxkIGxvb2sgbGlrZTogXFxuICAnICsgLy8gQnJlYWsgdXAgaW1wb3J0cyB0byBhdm9pZCBhY2NpZGVudGFsbHkgcGFyc2luZyB0aGVtIGFzIGRlcGVuZGVuY2llcy5cbiAgICAgICAgJ2NvbnN0IE15Q29tcG9uZW50ID0gbGF6eSgoKSA9PiBpbXAnICsgXCJvcnQoJy4vTXlDb21wb25lbnQnKSlcXG5cXG5cIiArICdEaWQgeW91IGFjY2lkZW50YWxseSBwdXQgY3VybHkgYnJhY2VzIGFyb3VuZCB0aGUgaW1wb3J0PycsIG1vZHVsZU9iamVjdCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAge1xuICAgICAgaWYgKCEoJ2RlZmF1bHQnIGluIG1vZHVsZU9iamVjdCkpIHtcbiAgICAgICAgZXJyb3IoJ2xhenk6IEV4cGVjdGVkIHRoZSByZXN1bHQgb2YgYSBkeW5hbWljIGltcCcgKyAnb3J0KCkgY2FsbC4gJyArICdJbnN0ZWFkIHJlY2VpdmVkOiAlc1xcblxcbllvdXIgY29kZSBzaG91bGQgbG9vayBsaWtlOiBcXG4gICcgKyAvLyBCcmVhayB1cCBpbXBvcnRzIHRvIGF2b2lkIGFjY2lkZW50YWxseSBwYXJzaW5nIHRoZW0gYXMgZGVwZW5kZW5jaWVzLlxuICAgICAgICAnY29uc3QgTXlDb21wb25lbnQgPSBsYXp5KCgpID0+IGltcCcgKyBcIm9ydCgnLi9NeUNvbXBvbmVudCcpKVwiLCBtb2R1bGVPYmplY3QpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBtb2R1bGVPYmplY3QuZGVmYXVsdDtcbiAgfSBlbHNlIHtcbiAgICB0aHJvdyBwYXlsb2FkLl9yZXN1bHQ7XG4gIH1cbn1cblxuZnVuY3Rpb24gbGF6eShjdG9yKSB7XG4gIHZhciBwYXlsb2FkID0ge1xuICAgIC8vIFdlIHVzZSB0aGVzZSBmaWVsZHMgdG8gc3RvcmUgdGhlIHJlc3VsdC5cbiAgICBfc3RhdHVzOiBVbmluaXRpYWxpemVkLFxuICAgIF9yZXN1bHQ6IGN0b3JcbiAgfTtcbiAgdmFyIGxhenlUeXBlID0ge1xuICAgICQkdHlwZW9mOiBSRUFDVF9MQVpZX1RZUEUsXG4gICAgX3BheWxvYWQ6IHBheWxvYWQsXG4gICAgX2luaXQ6IGxhenlJbml0aWFsaXplclxuICB9O1xuXG4gIHtcbiAgICAvLyBJbiBwcm9kdWN0aW9uLCB0aGlzIHdvdWxkIGp1c3Qgc2V0IGl0IG9uIHRoZSBvYmplY3QuXG4gICAgdmFyIGRlZmF1bHRQcm9wcztcbiAgICB2YXIgcHJvcFR5cGVzOyAvLyAkRmxvd0ZpeE1lXG5cbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydGllcyhsYXp5VHlwZSwge1xuICAgICAgZGVmYXVsdFByb3BzOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZSxcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuIGRlZmF1bHRQcm9wcztcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAobmV3RGVmYXVsdFByb3BzKSB7XG4gICAgICAgICAgZXJyb3IoJ1JlYWN0LmxhenkoLi4uKTogSXQgaXMgbm90IHN1cHBvcnRlZCB0byBhc3NpZ24gYGRlZmF1bHRQcm9wc2AgdG8gJyArICdhIGxhenkgY29tcG9uZW50IGltcG9ydC4gRWl0aGVyIHNwZWNpZnkgdGhlbSB3aGVyZSB0aGUgY29tcG9uZW50ICcgKyAnaXMgZGVmaW5lZCwgb3IgY3JlYXRlIGEgd3JhcHBpbmcgY29tcG9uZW50IGFyb3VuZCBpdC4nKTtcblxuICAgICAgICAgIGRlZmF1bHRQcm9wcyA9IG5ld0RlZmF1bHRQcm9wczsgLy8gTWF0Y2ggcHJvZHVjdGlvbiBiZWhhdmlvciBtb3JlIGNsb3NlbHk6XG4gICAgICAgICAgLy8gJEZsb3dGaXhNZVxuXG4gICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGxhenlUeXBlLCAnZGVmYXVsdFByb3BzJywge1xuICAgICAgICAgICAgZW51bWVyYWJsZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvcFR5cGVzOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZSxcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuIHByb3BUeXBlcztcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAobmV3UHJvcFR5cGVzKSB7XG4gICAgICAgICAgZXJyb3IoJ1JlYWN0LmxhenkoLi4uKTogSXQgaXMgbm90IHN1cHBvcnRlZCB0byBhc3NpZ24gYHByb3BUeXBlc2AgdG8gJyArICdhIGxhenkgY29tcG9uZW50IGltcG9ydC4gRWl0aGVyIHNwZWNpZnkgdGhlbSB3aGVyZSB0aGUgY29tcG9uZW50ICcgKyAnaXMgZGVmaW5lZCwgb3IgY3JlYXRlIGEgd3JhcHBpbmcgY29tcG9uZW50IGFyb3VuZCBpdC4nKTtcblxuICAgICAgICAgIHByb3BUeXBlcyA9IG5ld1Byb3BUeXBlczsgLy8gTWF0Y2ggcHJvZHVjdGlvbiBiZWhhdmlvciBtb3JlIGNsb3NlbHk6XG4gICAgICAgICAgLy8gJEZsb3dGaXhNZVxuXG4gICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGxhenlUeXBlLCAncHJvcFR5cGVzJywge1xuICAgICAgICAgICAgZW51bWVyYWJsZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICByZXR1cm4gbGF6eVR5cGU7XG59XG5cbmZ1bmN0aW9uIGZvcndhcmRSZWYocmVuZGVyKSB7XG4gIHtcbiAgICBpZiAocmVuZGVyICE9IG51bGwgJiYgcmVuZGVyLiQkdHlwZW9mID09PSBSRUFDVF9NRU1PX1RZUEUpIHtcbiAgICAgIGVycm9yKCdmb3J3YXJkUmVmIHJlcXVpcmVzIGEgcmVuZGVyIGZ1bmN0aW9uIGJ1dCByZWNlaXZlZCBhIGBtZW1vYCAnICsgJ2NvbXBvbmVudC4gSW5zdGVhZCBvZiBmb3J3YXJkUmVmKG1lbW8oLi4uKSksIHVzZSAnICsgJ21lbW8oZm9yd2FyZFJlZiguLi4pKS4nKTtcbiAgICB9IGVsc2UgaWYgKHR5cGVvZiByZW5kZXIgIT09ICdmdW5jdGlvbicpIHtcbiAgICAgIGVycm9yKCdmb3J3YXJkUmVmIHJlcXVpcmVzIGEgcmVuZGVyIGZ1bmN0aW9uIGJ1dCB3YXMgZ2l2ZW4gJXMuJywgcmVuZGVyID09PSBudWxsID8gJ251bGwnIDogdHlwZW9mIHJlbmRlcik7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChyZW5kZXIubGVuZ3RoICE9PSAwICYmIHJlbmRlci5sZW5ndGggIT09IDIpIHtcbiAgICAgICAgZXJyb3IoJ2ZvcndhcmRSZWYgcmVuZGVyIGZ1bmN0aW9ucyBhY2NlcHQgZXhhY3RseSB0d28gcGFyYW1ldGVyczogcHJvcHMgYW5kIHJlZi4gJXMnLCByZW5kZXIubGVuZ3RoID09PSAxID8gJ0RpZCB5b3UgZm9yZ2V0IHRvIHVzZSB0aGUgcmVmIHBhcmFtZXRlcj8nIDogJ0FueSBhZGRpdGlvbmFsIHBhcmFtZXRlciB3aWxsIGJlIHVuZGVmaW5lZC4nKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAocmVuZGVyICE9IG51bGwpIHtcbiAgICAgIGlmIChyZW5kZXIuZGVmYXVsdFByb3BzICE9IG51bGwgfHwgcmVuZGVyLnByb3BUeXBlcyAhPSBudWxsKSB7XG4gICAgICAgIGVycm9yKCdmb3J3YXJkUmVmIHJlbmRlciBmdW5jdGlvbnMgZG8gbm90IHN1cHBvcnQgcHJvcFR5cGVzIG9yIGRlZmF1bHRQcm9wcy4gJyArICdEaWQgeW91IGFjY2lkZW50YWxseSBwYXNzIGEgUmVhY3QgY29tcG9uZW50PycpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHZhciBlbGVtZW50VHlwZSA9IHtcbiAgICAkJHR5cGVvZjogUkVBQ1RfRk9SV0FSRF9SRUZfVFlQRSxcbiAgICByZW5kZXI6IHJlbmRlclxuICB9O1xuXG4gIHtcbiAgICB2YXIgb3duTmFtZTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoZWxlbWVudFR5cGUsICdkaXNwbGF5TmFtZScsIHtcbiAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgY29uZmlndXJhYmxlOiB0cnVlLFxuICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBvd25OYW1lO1xuICAgICAgfSxcbiAgICAgIHNldDogZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgICAgb3duTmFtZSA9IG5hbWU7IC8vIFRoZSBpbm5lciBjb21wb25lbnQgc2hvdWxkbid0IGluaGVyaXQgdGhpcyBkaXNwbGF5IG5hbWUgaW4gbW9zdCBjYXNlcyxcbiAgICAgICAgLy8gYmVjYXVzZSB0aGUgY29tcG9uZW50IG1heSBiZSB1c2VkIGVsc2V3aGVyZS5cbiAgICAgICAgLy8gQnV0IGl0J3MgbmljZSBmb3IgYW5vbnltb3VzIGZ1bmN0aW9ucyB0byBpbmhlcml0IHRoZSBuYW1lLFxuICAgICAgICAvLyBzbyB0aGF0IG91ciBjb21wb25lbnQtc3RhY2sgZ2VuZXJhdGlvbiBsb2dpYyB3aWxsIGRpc3BsYXkgdGhlaXIgZnJhbWVzLlxuICAgICAgICAvLyBBbiBhbm9ueW1vdXMgZnVuY3Rpb24gZ2VuZXJhbGx5IHN1Z2dlc3RzIGEgcGF0dGVybiBsaWtlOlxuICAgICAgICAvLyAgIFJlYWN0LmZvcndhcmRSZWYoKHByb3BzLCByZWYpID0+IHsuLi59KTtcbiAgICAgICAgLy8gVGhpcyBraW5kIG9mIGlubmVyIGZ1bmN0aW9uIGlzIG5vdCB1c2VkIGVsc2V3aGVyZSBzbyB0aGUgc2lkZSBlZmZlY3QgaXMgb2theS5cblxuICAgICAgICBpZiAoIXJlbmRlci5uYW1lICYmICFyZW5kZXIuZGlzcGxheU5hbWUpIHtcbiAgICAgICAgICByZW5kZXIuZGlzcGxheU5hbWUgPSBuYW1lO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICByZXR1cm4gZWxlbWVudFR5cGU7XG59XG5cbnZhciBSRUFDVF9NT0RVTEVfUkVGRVJFTkNFO1xuXG57XG4gIFJFQUNUX01PRFVMRV9SRUZFUkVOQ0UgPSBTeW1ib2wuZm9yKCdyZWFjdC5tb2R1bGUucmVmZXJlbmNlJyk7XG59XG5cbmZ1bmN0aW9uIGlzVmFsaWRFbGVtZW50VHlwZSh0eXBlKSB7XG4gIGlmICh0eXBlb2YgdHlwZSA9PT0gJ3N0cmluZycgfHwgdHlwZW9mIHR5cGUgPT09ICdmdW5jdGlvbicpIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfSAvLyBOb3RlOiB0eXBlb2YgbWlnaHQgYmUgb3RoZXIgdGhhbiAnc3ltYm9sJyBvciAnbnVtYmVyJyAoZS5nLiBpZiBpdCdzIGEgcG9seWZpbGwpLlxuXG5cbiAgaWYgKHR5cGUgPT09IFJFQUNUX0ZSQUdNRU5UX1RZUEUgfHwgdHlwZSA9PT0gUkVBQ1RfUFJPRklMRVJfVFlQRSB8fCBlbmFibGVEZWJ1Z1RyYWNpbmcgIHx8IHR5cGUgPT09IFJFQUNUX1NUUklDVF9NT0RFX1RZUEUgfHwgdHlwZSA9PT0gUkVBQ1RfU1VTUEVOU0VfVFlQRSB8fCB0eXBlID09PSBSRUFDVF9TVVNQRU5TRV9MSVNUX1RZUEUgfHwgZW5hYmxlTGVnYWN5SGlkZGVuICB8fCB0eXBlID09PSBSRUFDVF9PRkZTQ1JFRU5fVFlQRSB8fCBlbmFibGVTY29wZUFQSSAgfHwgZW5hYmxlQ2FjaGVFbGVtZW50ICB8fCBlbmFibGVUcmFuc2l0aW9uVHJhY2luZyApIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIGlmICh0eXBlb2YgdHlwZSA9PT0gJ29iamVjdCcgJiYgdHlwZSAhPT0gbnVsbCkge1xuICAgIGlmICh0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9MQVpZX1RZUEUgfHwgdHlwZS4kJHR5cGVvZiA9PT0gUkVBQ1RfTUVNT19UWVBFIHx8IHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX1BST1ZJREVSX1RZUEUgfHwgdHlwZS4kJHR5cGVvZiA9PT0gUkVBQ1RfQ09OVEVYVF9UWVBFIHx8IHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX0ZPUldBUkRfUkVGX1RZUEUgfHwgLy8gVGhpcyBuZWVkcyB0byBpbmNsdWRlIGFsbCBwb3NzaWJsZSBtb2R1bGUgcmVmZXJlbmNlIG9iamVjdFxuICAgIC8vIHR5cGVzIHN1cHBvcnRlZCBieSBhbnkgRmxpZ2h0IGNvbmZpZ3VyYXRpb24gYW55d2hlcmUgc2luY2VcbiAgICAvLyB3ZSBkb24ndCBrbm93IHdoaWNoIEZsaWdodCBidWlsZCB0aGlzIHdpbGwgZW5kIHVwIGJlaW5nIHVzZWRcbiAgICAvLyB3aXRoLlxuICAgIHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX01PRFVMRV9SRUZFUkVOQ0UgfHwgdHlwZS5nZXRNb2R1bGVJZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZmFsc2U7XG59XG5cbmZ1bmN0aW9uIG1lbW8odHlwZSwgY29tcGFyZSkge1xuICB7XG4gICAgaWYgKCFpc1ZhbGlkRWxlbWVudFR5cGUodHlwZSkpIHtcbiAgICAgIGVycm9yKCdtZW1vOiBUaGUgZmlyc3QgYXJndW1lbnQgbXVzdCBiZSBhIGNvbXBvbmVudC4gSW5zdGVhZCAnICsgJ3JlY2VpdmVkOiAlcycsIHR5cGUgPT09IG51bGwgPyAnbnVsbCcgOiB0eXBlb2YgdHlwZSk7XG4gICAgfVxuICB9XG5cbiAgdmFyIGVsZW1lbnRUeXBlID0ge1xuICAgICQkdHlwZW9mOiBSRUFDVF9NRU1PX1RZUEUsXG4gICAgdHlwZTogdHlwZSxcbiAgICBjb21wYXJlOiBjb21wYXJlID09PSB1bmRlZmluZWQgPyBudWxsIDogY29tcGFyZVxuICB9O1xuXG4gIHtcbiAgICB2YXIgb3duTmFtZTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoZWxlbWVudFR5cGUsICdkaXNwbGF5TmFtZScsIHtcbiAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgY29uZmlndXJhYmxlOiB0cnVlLFxuICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBvd25OYW1lO1xuICAgICAgfSxcbiAgICAgIHNldDogZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgICAgb3duTmFtZSA9IG5hbWU7IC8vIFRoZSBpbm5lciBjb21wb25lbnQgc2hvdWxkbid0IGluaGVyaXQgdGhpcyBkaXNwbGF5IG5hbWUgaW4gbW9zdCBjYXNlcyxcbiAgICAgICAgLy8gYmVjYXVzZSB0aGUgY29tcG9uZW50IG1heSBiZSB1c2VkIGVsc2V3aGVyZS5cbiAgICAgICAgLy8gQnV0IGl0J3MgbmljZSBmb3IgYW5vbnltb3VzIGZ1bmN0aW9ucyB0byBpbmhlcml0IHRoZSBuYW1lLFxuICAgICAgICAvLyBzbyB0aGF0IG91ciBjb21wb25lbnQtc3RhY2sgZ2VuZXJhdGlvbiBsb2dpYyB3aWxsIGRpc3BsYXkgdGhlaXIgZnJhbWVzLlxuICAgICAgICAvLyBBbiBhbm9ueW1vdXMgZnVuY3Rpb24gZ2VuZXJhbGx5IHN1Z2dlc3RzIGEgcGF0dGVybiBsaWtlOlxuICAgICAgICAvLyAgIFJlYWN0Lm1lbW8oKHByb3BzKSA9PiB7Li4ufSk7XG4gICAgICAgIC8vIFRoaXMga2luZCBvZiBpbm5lciBmdW5jdGlvbiBpcyBub3QgdXNlZCBlbHNld2hlcmUgc28gdGhlIHNpZGUgZWZmZWN0IGlzIG9rYXkuXG5cbiAgICAgICAgaWYgKCF0eXBlLm5hbWUgJiYgIXR5cGUuZGlzcGxheU5hbWUpIHtcbiAgICAgICAgICB0eXBlLmRpc3BsYXlOYW1lID0gbmFtZTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIGVsZW1lbnRUeXBlO1xufVxuXG5mdW5jdGlvbiByZXNvbHZlRGlzcGF0Y2hlcigpIHtcbiAgdmFyIGRpc3BhdGNoZXIgPSBSZWFjdEN1cnJlbnREaXNwYXRjaGVyLmN1cnJlbnQ7XG5cbiAge1xuICAgIGlmIChkaXNwYXRjaGVyID09PSBudWxsKSB7XG4gICAgICBlcnJvcignSW52YWxpZCBob29rIGNhbGwuIEhvb2tzIGNhbiBvbmx5IGJlIGNhbGxlZCBpbnNpZGUgb2YgdGhlIGJvZHkgb2YgYSBmdW5jdGlvbiBjb21wb25lbnQuIFRoaXMgY291bGQgaGFwcGVuIGZvcicgKyAnIG9uZSBvZiB0aGUgZm9sbG93aW5nIHJlYXNvbnM6XFxuJyArICcxLiBZb3UgbWlnaHQgaGF2ZSBtaXNtYXRjaGluZyB2ZXJzaW9ucyBvZiBSZWFjdCBhbmQgdGhlIHJlbmRlcmVyIChzdWNoIGFzIFJlYWN0IERPTSlcXG4nICsgJzIuIFlvdSBtaWdodCBiZSBicmVha2luZyB0aGUgUnVsZXMgb2YgSG9va3NcXG4nICsgJzMuIFlvdSBtaWdodCBoYXZlIG1vcmUgdGhhbiBvbmUgY29weSBvZiBSZWFjdCBpbiB0aGUgc2FtZSBhcHBcXG4nICsgJ1NlZSBodHRwczovL3JlYWN0anMub3JnL2xpbmsvaW52YWxpZC1ob29rLWNhbGwgZm9yIHRpcHMgYWJvdXQgaG93IHRvIGRlYnVnIGFuZCBmaXggdGhpcyBwcm9ibGVtLicpO1xuICAgIH1cbiAgfSAvLyBXaWxsIHJlc3VsdCBpbiBhIG51bGwgYWNjZXNzIGVycm9yIGlmIGFjY2Vzc2VkIG91dHNpZGUgcmVuZGVyIHBoYXNlLiBXZVxuICAvLyBpbnRlbnRpb25hbGx5IGRvbid0IHRocm93IG91ciBvd24gZXJyb3IgYmVjYXVzZSB0aGlzIGlzIGluIGEgaG90IHBhdGguXG4gIC8vIEFsc28gaGVscHMgZW5zdXJlIHRoaXMgaXMgaW5saW5lZC5cblxuXG4gIHJldHVybiBkaXNwYXRjaGVyO1xufVxuZnVuY3Rpb24gdXNlQ29udGV4dChDb250ZXh0KSB7XG4gIHZhciBkaXNwYXRjaGVyID0gcmVzb2x2ZURpc3BhdGNoZXIoKTtcblxuICB7XG4gICAgLy8gVE9ETzogYWRkIGEgbW9yZSBnZW5lcmljIHdhcm5pbmcgZm9yIGludmFsaWQgdmFsdWVzLlxuICAgIGlmIChDb250ZXh0Ll9jb250ZXh0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIHZhciByZWFsQ29udGV4dCA9IENvbnRleHQuX2NvbnRleHQ7IC8vIERvbid0IGRlZHVwbGljYXRlIGJlY2F1c2UgdGhpcyBsZWdpdGltYXRlbHkgY2F1c2VzIGJ1Z3NcbiAgICAgIC8vIGFuZCBub2JvZHkgc2hvdWxkIGJlIHVzaW5nIHRoaXMgaW4gZXhpc3RpbmcgY29kZS5cblxuICAgICAgaWYgKHJlYWxDb250ZXh0LkNvbnN1bWVyID09PSBDb250ZXh0KSB7XG4gICAgICAgIGVycm9yKCdDYWxsaW5nIHVzZUNvbnRleHQoQ29udGV4dC5Db25zdW1lcikgaXMgbm90IHN1cHBvcnRlZCwgbWF5IGNhdXNlIGJ1Z3MsIGFuZCB3aWxsIGJlICcgKyAncmVtb3ZlZCBpbiBhIGZ1dHVyZSBtYWpvciByZWxlYXNlLiBEaWQgeW91IG1lYW4gdG8gY2FsbCB1c2VDb250ZXh0KENvbnRleHQpIGluc3RlYWQ/Jyk7XG4gICAgICB9IGVsc2UgaWYgKHJlYWxDb250ZXh0LlByb3ZpZGVyID09PSBDb250ZXh0KSB7XG4gICAgICAgIGVycm9yKCdDYWxsaW5nIHVzZUNvbnRleHQoQ29udGV4dC5Qcm92aWRlcikgaXMgbm90IHN1cHBvcnRlZC4gJyArICdEaWQgeW91IG1lYW4gdG8gY2FsbCB1c2VDb250ZXh0KENvbnRleHQpIGluc3RlYWQ/Jyk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGRpc3BhdGNoZXIudXNlQ29udGV4dChDb250ZXh0KTtcbn1cbmZ1bmN0aW9uIHVzZVN0YXRlKGluaXRpYWxTdGF0ZSkge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZVN0YXRlKGluaXRpYWxTdGF0ZSk7XG59XG5mdW5jdGlvbiB1c2VSZWR1Y2VyKHJlZHVjZXIsIGluaXRpYWxBcmcsIGluaXQpIHtcbiAgdmFyIGRpc3BhdGNoZXIgPSByZXNvbHZlRGlzcGF0Y2hlcigpO1xuICByZXR1cm4gZGlzcGF0Y2hlci51c2VSZWR1Y2VyKHJlZHVjZXIsIGluaXRpYWxBcmcsIGluaXQpO1xufVxuZnVuY3Rpb24gdXNlUmVmKGluaXRpYWxWYWx1ZSkge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZVJlZihpbml0aWFsVmFsdWUpO1xufVxuZnVuY3Rpb24gdXNlRWZmZWN0KGNyZWF0ZSwgZGVwcykge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZUVmZmVjdChjcmVhdGUsIGRlcHMpO1xufVxuZnVuY3Rpb24gdXNlSW5zZXJ0aW9uRWZmZWN0KGNyZWF0ZSwgZGVwcykge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZUluc2VydGlvbkVmZmVjdChjcmVhdGUsIGRlcHMpO1xufVxuZnVuY3Rpb24gdXNlTGF5b3V0RWZmZWN0KGNyZWF0ZSwgZGVwcykge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZUxheW91dEVmZmVjdChjcmVhdGUsIGRlcHMpO1xufVxuZnVuY3Rpb24gdXNlQ2FsbGJhY2soY2FsbGJhY2ssIGRlcHMpIHtcbiAgdmFyIGRpc3BhdGNoZXIgPSByZXNvbHZlRGlzcGF0Y2hlcigpO1xuICByZXR1cm4gZGlzcGF0Y2hlci51c2VDYWxsYmFjayhjYWxsYmFjaywgZGVwcyk7XG59XG5mdW5jdGlvbiB1c2VNZW1vKGNyZWF0ZSwgZGVwcykge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZU1lbW8oY3JlYXRlLCBkZXBzKTtcbn1cbmZ1bmN0aW9uIHVzZUltcGVyYXRpdmVIYW5kbGUocmVmLCBjcmVhdGUsIGRlcHMpIHtcbiAgdmFyIGRpc3BhdGNoZXIgPSByZXNvbHZlRGlzcGF0Y2hlcigpO1xuICByZXR1cm4gZGlzcGF0Y2hlci51c2VJbXBlcmF0aXZlSGFuZGxlKHJlZiwgY3JlYXRlLCBkZXBzKTtcbn1cbmZ1bmN0aW9uIHVzZURlYnVnVmFsdWUodmFsdWUsIGZvcm1hdHRlckZuKSB7XG4gIHtcbiAgICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gICAgcmV0dXJuIGRpc3BhdGNoZXIudXNlRGVidWdWYWx1ZSh2YWx1ZSwgZm9ybWF0dGVyRm4pO1xuICB9XG59XG5mdW5jdGlvbiB1c2VUcmFuc2l0aW9uKCkge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZVRyYW5zaXRpb24oKTtcbn1cbmZ1bmN0aW9uIHVzZURlZmVycmVkVmFsdWUodmFsdWUpIHtcbiAgdmFyIGRpc3BhdGNoZXIgPSByZXNvbHZlRGlzcGF0Y2hlcigpO1xuICByZXR1cm4gZGlzcGF0Y2hlci51c2VEZWZlcnJlZFZhbHVlKHZhbHVlKTtcbn1cbmZ1bmN0aW9uIHVzZUlkKCkge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZUlkKCk7XG59XG5mdW5jdGlvbiB1c2VTeW5jRXh0ZXJuYWxTdG9yZShzdWJzY3JpYmUsIGdldFNuYXBzaG90LCBnZXRTZXJ2ZXJTbmFwc2hvdCkge1xuICB2YXIgZGlzcGF0Y2hlciA9IHJlc29sdmVEaXNwYXRjaGVyKCk7XG4gIHJldHVybiBkaXNwYXRjaGVyLnVzZVN5bmNFeHRlcm5hbFN0b3JlKHN1YnNjcmliZSwgZ2V0U25hcHNob3QsIGdldFNlcnZlclNuYXBzaG90KTtcbn1cblxuLy8gSGVscGVycyB0byBwYXRjaCBjb25zb2xlLmxvZ3MgdG8gYXZvaWQgbG9nZ2luZyBkdXJpbmcgc2lkZS1lZmZlY3QgZnJlZVxuLy8gcmVwbGF5aW5nIG9uIHJlbmRlciBmdW5jdGlvbi4gVGhpcyBjdXJyZW50bHkgb25seSBwYXRjaGVzIHRoZSBvYmplY3Rcbi8vIGxhemlseSB3aGljaCB3b24ndCBjb3ZlciBpZiB0aGUgbG9nIGZ1bmN0aW9uIHdhcyBleHRyYWN0ZWQgZWFnZXJseS5cbi8vIFdlIGNvdWxkIGFsc28gZWFnZXJseSBwYXRjaCB0aGUgbWV0aG9kLlxudmFyIGRpc2FibGVkRGVwdGggPSAwO1xudmFyIHByZXZMb2c7XG52YXIgcHJldkluZm87XG52YXIgcHJldldhcm47XG52YXIgcHJldkVycm9yO1xudmFyIHByZXZHcm91cDtcbnZhciBwcmV2R3JvdXBDb2xsYXBzZWQ7XG52YXIgcHJldkdyb3VwRW5kO1xuXG5mdW5jdGlvbiBkaXNhYmxlZExvZygpIHt9XG5cbmRpc2FibGVkTG9nLl9fcmVhY3REaXNhYmxlZExvZyA9IHRydWU7XG5mdW5jdGlvbiBkaXNhYmxlTG9ncygpIHtcbiAge1xuICAgIGlmIChkaXNhYmxlZERlcHRoID09PSAwKSB7XG4gICAgICAvKiBlc2xpbnQtZGlzYWJsZSByZWFjdC1pbnRlcm5hbC9uby1wcm9kdWN0aW9uLWxvZ2dpbmcgKi9cbiAgICAgIHByZXZMb2cgPSBjb25zb2xlLmxvZztcbiAgICAgIHByZXZJbmZvID0gY29uc29sZS5pbmZvO1xuICAgICAgcHJldldhcm4gPSBjb25zb2xlLndhcm47XG4gICAgICBwcmV2RXJyb3IgPSBjb25zb2xlLmVycm9yO1xuICAgICAgcHJldkdyb3VwID0gY29uc29sZS5ncm91cDtcbiAgICAgIHByZXZHcm91cENvbGxhcHNlZCA9IGNvbnNvbGUuZ3JvdXBDb2xsYXBzZWQ7XG4gICAgICBwcmV2R3JvdXBFbmQgPSBjb25zb2xlLmdyb3VwRW5kOyAvLyBodHRwczovL2dpdGh1Yi5jb20vZmFjZWJvb2svcmVhY3QvaXNzdWVzLzE5MDk5XG5cbiAgICAgIHZhciBwcm9wcyA9IHtcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlLFxuICAgICAgICBlbnVtZXJhYmxlOiB0cnVlLFxuICAgICAgICB2YWx1ZTogZGlzYWJsZWRMb2csXG4gICAgICAgIHdyaXRhYmxlOiB0cnVlXG4gICAgICB9OyAvLyAkRmxvd0ZpeE1lIEZsb3cgdGhpbmtzIGNvbnNvbGUgaXMgaW1tdXRhYmxlLlxuXG4gICAgICBPYmplY3QuZGVmaW5lUHJvcGVydGllcyhjb25zb2xlLCB7XG4gICAgICAgIGluZm86IHByb3BzLFxuICAgICAgICBsb2c6IHByb3BzLFxuICAgICAgICB3YXJuOiBwcm9wcyxcbiAgICAgICAgZXJyb3I6IHByb3BzLFxuICAgICAgICBncm91cDogcHJvcHMsXG4gICAgICAgIGdyb3VwQ29sbGFwc2VkOiBwcm9wcyxcbiAgICAgICAgZ3JvdXBFbmQ6IHByb3BzXG4gICAgICB9KTtcbiAgICAgIC8qIGVzbGludC1lbmFibGUgcmVhY3QtaW50ZXJuYWwvbm8tcHJvZHVjdGlvbi1sb2dnaW5nICovXG4gICAgfVxuXG4gICAgZGlzYWJsZWREZXB0aCsrO1xuICB9XG59XG5mdW5jdGlvbiByZWVuYWJsZUxvZ3MoKSB7XG4gIHtcbiAgICBkaXNhYmxlZERlcHRoLS07XG5cbiAgICBpZiAoZGlzYWJsZWREZXB0aCA9PT0gMCkge1xuICAgICAgLyogZXNsaW50LWRpc2FibGUgcmVhY3QtaW50ZXJuYWwvbm8tcHJvZHVjdGlvbi1sb2dnaW5nICovXG4gICAgICB2YXIgcHJvcHMgPSB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZSxcbiAgICAgICAgZW51bWVyYWJsZTogdHJ1ZSxcbiAgICAgICAgd3JpdGFibGU6IHRydWVcbiAgICAgIH07IC8vICRGbG93Rml4TWUgRmxvdyB0aGlua3MgY29uc29sZSBpcyBpbW11dGFibGUuXG5cbiAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0aWVzKGNvbnNvbGUsIHtcbiAgICAgICAgbG9nOiBhc3NpZ24oe30sIHByb3BzLCB7XG4gICAgICAgICAgdmFsdWU6IHByZXZMb2dcbiAgICAgICAgfSksXG4gICAgICAgIGluZm86IGFzc2lnbih7fSwgcHJvcHMsIHtcbiAgICAgICAgICB2YWx1ZTogcHJldkluZm9cbiAgICAgICAgfSksXG4gICAgICAgIHdhcm46IGFzc2lnbih7fSwgcHJvcHMsIHtcbiAgICAgICAgICB2YWx1ZTogcHJldldhcm5cbiAgICAgICAgfSksXG4gICAgICAgIGVycm9yOiBhc3NpZ24oe30sIHByb3BzLCB7XG4gICAgICAgICAgdmFsdWU6IHByZXZFcnJvclxuICAgICAgICB9KSxcbiAgICAgICAgZ3JvdXA6IGFzc2lnbih7fSwgcHJvcHMsIHtcbiAgICAgICAgICB2YWx1ZTogcHJldkdyb3VwXG4gICAgICAgIH0pLFxuICAgICAgICBncm91cENvbGxhcHNlZDogYXNzaWduKHt9LCBwcm9wcywge1xuICAgICAgICAgIHZhbHVlOiBwcmV2R3JvdXBDb2xsYXBzZWRcbiAgICAgICAgfSksXG4gICAgICAgIGdyb3VwRW5kOiBhc3NpZ24oe30sIHByb3BzLCB7XG4gICAgICAgICAgdmFsdWU6IHByZXZHcm91cEVuZFxuICAgICAgICB9KVxuICAgICAgfSk7XG4gICAgICAvKiBlc2xpbnQtZW5hYmxlIHJlYWN0LWludGVybmFsL25vLXByb2R1Y3Rpb24tbG9nZ2luZyAqL1xuICAgIH1cblxuICAgIGlmIChkaXNhYmxlZERlcHRoIDwgMCkge1xuICAgICAgZXJyb3IoJ2Rpc2FibGVkRGVwdGggZmVsbCBiZWxvdyB6ZXJvLiAnICsgJ1RoaXMgaXMgYSBidWcgaW4gUmVhY3QuIFBsZWFzZSBmaWxlIGFuIGlzc3VlLicpO1xuICAgIH1cbiAgfVxufVxuXG52YXIgUmVhY3RDdXJyZW50RGlzcGF0Y2hlciQxID0gUmVhY3RTaGFyZWRJbnRlcm5hbHMuUmVhY3RDdXJyZW50RGlzcGF0Y2hlcjtcbnZhciBwcmVmaXg7XG5mdW5jdGlvbiBkZXNjcmliZUJ1aWx0SW5Db21wb25lbnRGcmFtZShuYW1lLCBzb3VyY2UsIG93bmVyRm4pIHtcbiAge1xuICAgIGlmIChwcmVmaXggPT09IHVuZGVmaW5lZCkge1xuICAgICAgLy8gRXh0cmFjdCB0aGUgVk0gc3BlY2lmaWMgcHJlZml4IHVzZWQgYnkgZWFjaCBsaW5lLlxuICAgICAgdHJ5IHtcbiAgICAgICAgdGhyb3cgRXJyb3IoKTtcbiAgICAgIH0gY2F0Y2ggKHgpIHtcbiAgICAgICAgdmFyIG1hdGNoID0geC5zdGFjay50cmltKCkubWF0Y2goL1xcbiggKihhdCApPykvKTtcbiAgICAgICAgcHJlZml4ID0gbWF0Y2ggJiYgbWF0Y2hbMV0gfHwgJyc7XG4gICAgICB9XG4gICAgfSAvLyBXZSB1c2UgdGhlIHByZWZpeCB0byBlbnN1cmUgb3VyIHN0YWNrcyBsaW5lIHVwIHdpdGggbmF0aXZlIHN0YWNrIGZyYW1lcy5cblxuXG4gICAgcmV0dXJuICdcXG4nICsgcHJlZml4ICsgbmFtZTtcbiAgfVxufVxudmFyIHJlZW50cnkgPSBmYWxzZTtcbnZhciBjb21wb25lbnRGcmFtZUNhY2hlO1xuXG57XG4gIHZhciBQb3NzaWJseVdlYWtNYXAgPSB0eXBlb2YgV2Vha01hcCA9PT0gJ2Z1bmN0aW9uJyA/IFdlYWtNYXAgOiBNYXA7XG4gIGNvbXBvbmVudEZyYW1lQ2FjaGUgPSBuZXcgUG9zc2libHlXZWFrTWFwKCk7XG59XG5cbmZ1bmN0aW9uIGRlc2NyaWJlTmF0aXZlQ29tcG9uZW50RnJhbWUoZm4sIGNvbnN0cnVjdCkge1xuICAvLyBJZiBzb21ldGhpbmcgYXNrZWQgZm9yIGEgc3RhY2sgaW5zaWRlIGEgZmFrZSByZW5kZXIsIGl0IHNob3VsZCBnZXQgaWdub3JlZC5cbiAgaWYgKCAhZm4gfHwgcmVlbnRyeSkge1xuICAgIHJldHVybiAnJztcbiAgfVxuXG4gIHtcbiAgICB2YXIgZnJhbWUgPSBjb21wb25lbnRGcmFtZUNhY2hlLmdldChmbik7XG5cbiAgICBpZiAoZnJhbWUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIGZyYW1lO1xuICAgIH1cbiAgfVxuXG4gIHZhciBjb250cm9sO1xuICByZWVudHJ5ID0gdHJ1ZTtcbiAgdmFyIHByZXZpb3VzUHJlcGFyZVN0YWNrVHJhY2UgPSBFcnJvci5wcmVwYXJlU3RhY2tUcmFjZTsgLy8gJEZsb3dGaXhNZSBJdCBkb2VzIGFjY2VwdCB1bmRlZmluZWQuXG5cbiAgRXJyb3IucHJlcGFyZVN0YWNrVHJhY2UgPSB1bmRlZmluZWQ7XG4gIHZhciBwcmV2aW91c0Rpc3BhdGNoZXI7XG5cbiAge1xuICAgIHByZXZpb3VzRGlzcGF0Y2hlciA9IFJlYWN0Q3VycmVudERpc3BhdGNoZXIkMS5jdXJyZW50OyAvLyBTZXQgdGhlIGRpc3BhdGNoZXIgaW4gREVWIGJlY2F1c2UgdGhpcyBtaWdodCBiZSBjYWxsIGluIHRoZSByZW5kZXIgZnVuY3Rpb25cbiAgICAvLyBmb3Igd2FybmluZ3MuXG5cbiAgICBSZWFjdEN1cnJlbnREaXNwYXRjaGVyJDEuY3VycmVudCA9IG51bGw7XG4gICAgZGlzYWJsZUxvZ3MoKTtcbiAgfVxuXG4gIHRyeSB7XG4gICAgLy8gVGhpcyBzaG91bGQgdGhyb3cuXG4gICAgaWYgKGNvbnN0cnVjdCkge1xuICAgICAgLy8gU29tZXRoaW5nIHNob3VsZCBiZSBzZXR0aW5nIHRoZSBwcm9wcyBpbiB0aGUgY29uc3RydWN0b3IuXG4gICAgICB2YXIgRmFrZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhyb3cgRXJyb3IoKTtcbiAgICAgIH07IC8vICRGbG93Rml4TWVcblxuXG4gICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoRmFrZS5wcm90b3R5cGUsICdwcm9wcycsIHtcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgLy8gV2UgdXNlIGEgdGhyb3dpbmcgc2V0dGVyIGluc3RlYWQgb2YgZnJvemVuIG9yIG5vbi13cml0YWJsZSBwcm9wc1xuICAgICAgICAgIC8vIGJlY2F1c2UgdGhhdCB3b24ndCB0aHJvdyBpbiBhIG5vbi1zdHJpY3QgbW9kZSBmdW5jdGlvbi5cbiAgICAgICAgICB0aHJvdyBFcnJvcigpO1xuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSAnb2JqZWN0JyAmJiBSZWZsZWN0LmNvbnN0cnVjdCkge1xuICAgICAgICAvLyBXZSBjb25zdHJ1Y3QgYSBkaWZmZXJlbnQgY29udHJvbCBmb3IgdGhpcyBjYXNlIHRvIGluY2x1ZGUgYW55IGV4dHJhXG4gICAgICAgIC8vIGZyYW1lcyBhZGRlZCBieSB0aGUgY29uc3RydWN0IGNhbGwuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgUmVmbGVjdC5jb25zdHJ1Y3QoRmFrZSwgW10pO1xuICAgICAgICB9IGNhdGNoICh4KSB7XG4gICAgICAgICAgY29udHJvbCA9IHg7XG4gICAgICAgIH1cblxuICAgICAgICBSZWZsZWN0LmNvbnN0cnVjdChmbiwgW10sIEZha2UpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBGYWtlLmNhbGwoKTtcbiAgICAgICAgfSBjYXRjaCAoeCkge1xuICAgICAgICAgIGNvbnRyb2wgPSB4O1xuICAgICAgICB9XG5cbiAgICAgICAgZm4uY2FsbChGYWtlLnByb3RvdHlwZSk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIHRocm93IEVycm9yKCk7XG4gICAgICB9IGNhdGNoICh4KSB7XG4gICAgICAgIGNvbnRyb2wgPSB4O1xuICAgICAgfVxuXG4gICAgICBmbigpO1xuICAgIH1cbiAgfSBjYXRjaCAoc2FtcGxlKSB7XG4gICAgLy8gVGhpcyBpcyBpbmxpbmVkIG1hbnVhbGx5IGJlY2F1c2UgY2xvc3VyZSBkb2Vzbid0IGRvIGl0IGZvciB1cy5cbiAgICBpZiAoc2FtcGxlICYmIGNvbnRyb2wgJiYgdHlwZW9mIHNhbXBsZS5zdGFjayA9PT0gJ3N0cmluZycpIHtcbiAgICAgIC8vIFRoaXMgZXh0cmFjdHMgdGhlIGZpcnN0IGZyYW1lIGZyb20gdGhlIHNhbXBsZSB0aGF0IGlzbid0IGFsc28gaW4gdGhlIGNvbnRyb2wuXG4gICAgICAvLyBTa2lwcGluZyBvbmUgZnJhbWUgdGhhdCB3ZSBhc3N1bWUgaXMgdGhlIGZyYW1lIHRoYXQgY2FsbHMgdGhlIHR3by5cbiAgICAgIHZhciBzYW1wbGVMaW5lcyA9IHNhbXBsZS5zdGFjay5zcGxpdCgnXFxuJyk7XG4gICAgICB2YXIgY29udHJvbExpbmVzID0gY29udHJvbC5zdGFjay5zcGxpdCgnXFxuJyk7XG4gICAgICB2YXIgcyA9IHNhbXBsZUxpbmVzLmxlbmd0aCAtIDE7XG4gICAgICB2YXIgYyA9IGNvbnRyb2xMaW5lcy5sZW5ndGggLSAxO1xuXG4gICAgICB3aGlsZSAocyA+PSAxICYmIGMgPj0gMCAmJiBzYW1wbGVMaW5lc1tzXSAhPT0gY29udHJvbExpbmVzW2NdKSB7XG4gICAgICAgIC8vIFdlIGV4cGVjdCBhdCBsZWFzdCBvbmUgc3RhY2sgZnJhbWUgdG8gYmUgc2hhcmVkLlxuICAgICAgICAvLyBUeXBpY2FsbHkgdGhpcyB3aWxsIGJlIHRoZSByb290IG1vc3Qgb25lLiBIb3dldmVyLCBzdGFjayBmcmFtZXMgbWF5IGJlXG4gICAgICAgIC8vIGN1dCBvZmYgZHVlIHRvIG1heGltdW0gc3RhY2sgbGltaXRzLiBJbiB0aGlzIGNhc2UsIG9uZSBtYXliZSBjdXQgb2ZmXG4gICAgICAgIC8vIGVhcmxpZXIgdGhhbiB0aGUgb3RoZXIuIFdlIGFzc3VtZSB0aGF0IHRoZSBzYW1wbGUgaXMgbG9uZ2VyIG9yIHRoZSBzYW1lXG4gICAgICAgIC8vIGFuZCB0aGVyZSBmb3IgY3V0IG9mZiBlYXJsaWVyLiBTbyB3ZSBzaG91bGQgZmluZCB0aGUgcm9vdCBtb3N0IGZyYW1lIGluXG4gICAgICAgIC8vIHRoZSBzYW1wbGUgc29tZXdoZXJlIGluIHRoZSBjb250cm9sLlxuICAgICAgICBjLS07XG4gICAgICB9XG5cbiAgICAgIGZvciAoOyBzID49IDEgJiYgYyA+PSAwOyBzLS0sIGMtLSkge1xuICAgICAgICAvLyBOZXh0IHdlIGZpbmQgdGhlIGZpcnN0IG9uZSB0aGF0IGlzbid0IHRoZSBzYW1lIHdoaWNoIHNob3VsZCBiZSB0aGVcbiAgICAgICAgLy8gZnJhbWUgdGhhdCBjYWxsZWQgb3VyIHNhbXBsZSBmdW5jdGlvbiBhbmQgdGhlIGNvbnRyb2wuXG4gICAgICAgIGlmIChzYW1wbGVMaW5lc1tzXSAhPT0gY29udHJvbExpbmVzW2NdKSB7XG4gICAgICAgICAgLy8gSW4gVjgsIHRoZSBmaXJzdCBsaW5lIGlzIGRlc2NyaWJpbmcgdGhlIG1lc3NhZ2UgYnV0IG90aGVyIFZNcyBkb24ndC5cbiAgICAgICAgICAvLyBJZiB3ZSdyZSBhYm91dCB0byByZXR1cm4gdGhlIGZpcnN0IGxpbmUsIGFuZCB0aGUgY29udHJvbCBpcyBhbHNvIG9uIHRoZSBzYW1lXG4gICAgICAgICAgLy8gbGluZSwgdGhhdCdzIGEgcHJldHR5IGdvb2QgaW5kaWNhdG9yIHRoYXQgb3VyIHNhbXBsZSB0aHJldyBhdCBzYW1lIGxpbmUgYXNcbiAgICAgICAgICAvLyB0aGUgY29udHJvbC4gSS5lLiBiZWZvcmUgd2UgZW50ZXJlZCB0aGUgc2FtcGxlIGZyYW1lLiBTbyB3ZSBpZ25vcmUgdGhpcyByZXN1bHQuXG4gICAgICAgICAgLy8gVGhpcyBjYW4gaGFwcGVuIGlmIHlvdSBwYXNzZWQgYSBjbGFzcyB0byBmdW5jdGlvbiBjb21wb25lbnQsIG9yIG5vbi1mdW5jdGlvbi5cbiAgICAgICAgICBpZiAocyAhPT0gMSB8fCBjICE9PSAxKSB7XG4gICAgICAgICAgICBkbyB7XG4gICAgICAgICAgICAgIHMtLTtcbiAgICAgICAgICAgICAgYy0tOyAvLyBXZSBtYXkgc3RpbGwgaGF2ZSBzaW1pbGFyIGludGVybWVkaWF0ZSBmcmFtZXMgZnJvbSB0aGUgY29uc3RydWN0IGNhbGwuXG4gICAgICAgICAgICAgIC8vIFRoZSBuZXh0IG9uZSB0aGF0IGlzbid0IHRoZSBzYW1lIHNob3VsZCBiZSBvdXIgbWF0Y2ggdGhvdWdoLlxuXG4gICAgICAgICAgICAgIGlmIChjIDwgMCB8fCBzYW1wbGVMaW5lc1tzXSAhPT0gY29udHJvbExpbmVzW2NdKSB7XG4gICAgICAgICAgICAgICAgLy8gVjggYWRkcyBhIFwibmV3XCIgcHJlZml4IGZvciBuYXRpdmUgY2xhc3Nlcy4gTGV0J3MgcmVtb3ZlIGl0IHRvIG1ha2UgaXQgcHJldHRpZXIuXG4gICAgICAgICAgICAgICAgdmFyIF9mcmFtZSA9ICdcXG4nICsgc2FtcGxlTGluZXNbc10ucmVwbGFjZSgnIGF0IG5ldyAnLCAnIGF0ICcpOyAvLyBJZiBvdXIgY29tcG9uZW50IGZyYW1lIGlzIGxhYmVsZWQgXCI8YW5vbnltb3VzPlwiXG4gICAgICAgICAgICAgICAgLy8gYnV0IHdlIGhhdmUgYSB1c2VyLXByb3ZpZGVkIFwiZGlzcGxheU5hbWVcIlxuICAgICAgICAgICAgICAgIC8vIHNwbGljZSBpdCBpbiB0byBtYWtlIHRoZSBzdGFjayBtb3JlIHJlYWRhYmxlLlxuXG5cbiAgICAgICAgICAgICAgICBpZiAoZm4uZGlzcGxheU5hbWUgJiYgX2ZyYW1lLmluY2x1ZGVzKCc8YW5vbnltb3VzPicpKSB7XG4gICAgICAgICAgICAgICAgICBfZnJhbWUgPSBfZnJhbWUucmVwbGFjZSgnPGFub255bW91cz4nLCBmbi5kaXNwbGF5TmFtZSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBmbiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICAgICAgICBjb21wb25lbnRGcmFtZUNhY2hlLnNldChmbiwgX2ZyYW1lKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9IC8vIFJldHVybiB0aGUgbGluZSB3ZSBmb3VuZC5cblxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIF9mcmFtZTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSB3aGlsZSAocyA+PSAxICYmIGMgPj0gMCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH0gZmluYWxseSB7XG4gICAgcmVlbnRyeSA9IGZhbHNlO1xuXG4gICAge1xuICAgICAgUmVhY3RDdXJyZW50RGlzcGF0Y2hlciQxLmN1cnJlbnQgPSBwcmV2aW91c0Rpc3BhdGNoZXI7XG4gICAgICByZWVuYWJsZUxvZ3MoKTtcbiAgICB9XG5cbiAgICBFcnJvci5wcmVwYXJlU3RhY2tUcmFjZSA9IHByZXZpb3VzUHJlcGFyZVN0YWNrVHJhY2U7XG4gIH0gLy8gRmFsbGJhY2sgdG8ganVzdCB1c2luZyB0aGUgbmFtZSBpZiB3ZSBjb3VsZG4ndCBtYWtlIGl0IHRocm93LlxuXG5cbiAgdmFyIG5hbWUgPSBmbiA/IGZuLmRpc3BsYXlOYW1lIHx8IGZuLm5hbWUgOiAnJztcbiAgdmFyIHN5bnRoZXRpY0ZyYW1lID0gbmFtZSA/IGRlc2NyaWJlQnVpbHRJbkNvbXBvbmVudEZyYW1lKG5hbWUpIDogJyc7XG5cbiAge1xuICAgIGlmICh0eXBlb2YgZm4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIGNvbXBvbmVudEZyYW1lQ2FjaGUuc2V0KGZuLCBzeW50aGV0aWNGcmFtZSk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHN5bnRoZXRpY0ZyYW1lO1xufVxuZnVuY3Rpb24gZGVzY3JpYmVGdW5jdGlvbkNvbXBvbmVudEZyYW1lKGZuLCBzb3VyY2UsIG93bmVyRm4pIHtcbiAge1xuICAgIHJldHVybiBkZXNjcmliZU5hdGl2ZUNvbXBvbmVudEZyYW1lKGZuLCBmYWxzZSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2hvdWxkQ29uc3RydWN0KENvbXBvbmVudCkge1xuICB2YXIgcHJvdG90eXBlID0gQ29tcG9uZW50LnByb3RvdHlwZTtcbiAgcmV0dXJuICEhKHByb3RvdHlwZSAmJiBwcm90b3R5cGUuaXNSZWFjdENvbXBvbmVudCk7XG59XG5cbmZ1bmN0aW9uIGRlc2NyaWJlVW5rbm93bkVsZW1lbnRUeXBlRnJhbWVJbkRFVih0eXBlLCBzb3VyY2UsIG93bmVyRm4pIHtcblxuICBpZiAodHlwZSA9PSBudWxsKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG5cbiAgaWYgKHR5cGVvZiB0eXBlID09PSAnZnVuY3Rpb24nKSB7XG4gICAge1xuICAgICAgcmV0dXJuIGRlc2NyaWJlTmF0aXZlQ29tcG9uZW50RnJhbWUodHlwZSwgc2hvdWxkQ29uc3RydWN0KHR5cGUpKTtcbiAgICB9XG4gIH1cblxuICBpZiAodHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIGRlc2NyaWJlQnVpbHRJbkNvbXBvbmVudEZyYW1lKHR5cGUpO1xuICB9XG5cbiAgc3dpdGNoICh0eXBlKSB7XG4gICAgY2FzZSBSRUFDVF9TVVNQRU5TRV9UWVBFOlxuICAgICAgcmV0dXJuIGRlc2NyaWJlQnVpbHRJbkNvbXBvbmVudEZyYW1lKCdTdXNwZW5zZScpO1xuXG4gICAgY2FzZSBSRUFDVF9TVVNQRU5TRV9MSVNUX1RZUEU6XG4gICAgICByZXR1cm4gZGVzY3JpYmVCdWlsdEluQ29tcG9uZW50RnJhbWUoJ1N1c3BlbnNlTGlzdCcpO1xuICB9XG5cbiAgaWYgKHR5cGVvZiB0eXBlID09PSAnb2JqZWN0Jykge1xuICAgIHN3aXRjaCAodHlwZS4kJHR5cGVvZikge1xuICAgICAgY2FzZSBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFOlxuICAgICAgICByZXR1cm4gZGVzY3JpYmVGdW5jdGlvbkNvbXBvbmVudEZyYW1lKHR5cGUucmVuZGVyKTtcblxuICAgICAgY2FzZSBSRUFDVF9NRU1PX1RZUEU6XG4gICAgICAgIC8vIE1lbW8gbWF5IGNvbnRhaW4gYW55IGNvbXBvbmVudCB0eXBlIHNvIHdlIHJlY3Vyc2l2ZWx5IHJlc29sdmUgaXQuXG4gICAgICAgIHJldHVybiBkZXNjcmliZVVua25vd25FbGVtZW50VHlwZUZyYW1lSW5ERVYodHlwZS50eXBlLCBzb3VyY2UsIG93bmVyRm4pO1xuXG4gICAgICBjYXNlIFJFQUNUX0xBWllfVFlQRTpcbiAgICAgICAge1xuICAgICAgICAgIHZhciBsYXp5Q29tcG9uZW50ID0gdHlwZTtcbiAgICAgICAgICB2YXIgcGF5bG9hZCA9IGxhenlDb21wb25lbnQuX3BheWxvYWQ7XG4gICAgICAgICAgdmFyIGluaXQgPSBsYXp5Q29tcG9uZW50Ll9pbml0O1xuXG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIC8vIExhenkgbWF5IGNvbnRhaW4gYW55IGNvbXBvbmVudCB0eXBlIHNvIHdlIHJlY3Vyc2l2ZWx5IHJlc29sdmUgaXQuXG4gICAgICAgICAgICByZXR1cm4gZGVzY3JpYmVVbmtub3duRWxlbWVudFR5cGVGcmFtZUluREVWKGluaXQocGF5bG9hZCksIHNvdXJjZSwgb3duZXJGbik7XG4gICAgICAgICAgfSBjYXRjaCAoeCkge31cbiAgICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiAnJztcbn1cblxudmFyIGxvZ2dlZFR5cGVGYWlsdXJlcyA9IHt9O1xudmFyIFJlYWN0RGVidWdDdXJyZW50RnJhbWUkMSA9IFJlYWN0U2hhcmVkSW50ZXJuYWxzLlJlYWN0RGVidWdDdXJyZW50RnJhbWU7XG5cbmZ1bmN0aW9uIHNldEN1cnJlbnRseVZhbGlkYXRpbmdFbGVtZW50KGVsZW1lbnQpIHtcbiAge1xuICAgIGlmIChlbGVtZW50KSB7XG4gICAgICB2YXIgb3duZXIgPSBlbGVtZW50Ll9vd25lcjtcbiAgICAgIHZhciBzdGFjayA9IGRlc2NyaWJlVW5rbm93bkVsZW1lbnRUeXBlRnJhbWVJbkRFVihlbGVtZW50LnR5cGUsIGVsZW1lbnQuX3NvdXJjZSwgb3duZXIgPyBvd25lci50eXBlIDogbnVsbCk7XG4gICAgICBSZWFjdERlYnVnQ3VycmVudEZyYW1lJDEuc2V0RXh0cmFTdGFja0ZyYW1lKHN0YWNrKTtcbiAgICB9IGVsc2Uge1xuICAgICAgUmVhY3REZWJ1Z0N1cnJlbnRGcmFtZSQxLnNldEV4dHJhU3RhY2tGcmFtZShudWxsKTtcbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gY2hlY2tQcm9wVHlwZXModHlwZVNwZWNzLCB2YWx1ZXMsIGxvY2F0aW9uLCBjb21wb25lbnROYW1lLCBlbGVtZW50KSB7XG4gIHtcbiAgICAvLyAkRmxvd0ZpeE1lIFRoaXMgaXMgb2theSBidXQgRmxvdyBkb2Vzbid0IGtub3cgaXQuXG4gICAgdmFyIGhhcyA9IEZ1bmN0aW9uLmNhbGwuYmluZChoYXNPd25Qcm9wZXJ0eSk7XG5cbiAgICBmb3IgKHZhciB0eXBlU3BlY05hbWUgaW4gdHlwZVNwZWNzKSB7XG4gICAgICBpZiAoaGFzKHR5cGVTcGVjcywgdHlwZVNwZWNOYW1lKSkge1xuICAgICAgICB2YXIgZXJyb3IkMSA9IHZvaWQgMDsgLy8gUHJvcCB0eXBlIHZhbGlkYXRpb24gbWF5IHRocm93LiBJbiBjYXNlIHRoZXkgZG8sIHdlIGRvbid0IHdhbnQgdG9cbiAgICAgICAgLy8gZmFpbCB0aGUgcmVuZGVyIHBoYXNlIHdoZXJlIGl0IGRpZG4ndCBmYWlsIGJlZm9yZS4gU28gd2UgbG9nIGl0LlxuICAgICAgICAvLyBBZnRlciB0aGVzZSBoYXZlIGJlZW4gY2xlYW5lZCB1cCwgd2UnbGwgbGV0IHRoZW0gdGhyb3cuXG5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAvLyBUaGlzIGlzIGludGVudGlvbmFsbHkgYW4gaW52YXJpYW50IHRoYXQgZ2V0cyBjYXVnaHQuIEl0J3MgdGhlIHNhbWVcbiAgICAgICAgICAvLyBiZWhhdmlvciBhcyB3aXRob3V0IHRoaXMgc3RhdGVtZW50IGV4Y2VwdCB3aXRoIGEgYmV0dGVyIG1lc3NhZ2UuXG4gICAgICAgICAgaWYgKHR5cGVvZiB0eXBlU3BlY3NbdHlwZVNwZWNOYW1lXSAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIHJlYWN0LWludGVybmFsL3Byb2QtZXJyb3ItY29kZXNcbiAgICAgICAgICAgIHZhciBlcnIgPSBFcnJvcigoY29tcG9uZW50TmFtZSB8fCAnUmVhY3QgY2xhc3MnKSArICc6ICcgKyBsb2NhdGlvbiArICcgdHlwZSBgJyArIHR5cGVTcGVjTmFtZSArICdgIGlzIGludmFsaWQ7ICcgKyAnaXQgbXVzdCBiZSBhIGZ1bmN0aW9uLCB1c3VhbGx5IGZyb20gdGhlIGBwcm9wLXR5cGVzYCBwYWNrYWdlLCBidXQgcmVjZWl2ZWQgYCcgKyB0eXBlb2YgdHlwZVNwZWNzW3R5cGVTcGVjTmFtZV0gKyAnYC4nICsgJ1RoaXMgb2Z0ZW4gaGFwcGVucyBiZWNhdXNlIG9mIHR5cG9zIHN1Y2ggYXMgYFByb3BUeXBlcy5mdW5jdGlvbmAgaW5zdGVhZCBvZiBgUHJvcFR5cGVzLmZ1bmNgLicpO1xuICAgICAgICAgICAgZXJyLm5hbWUgPSAnSW52YXJpYW50IFZpb2xhdGlvbic7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXJyb3IkMSA9IHR5cGVTcGVjc1t0eXBlU3BlY05hbWVdKHZhbHVlcywgdHlwZVNwZWNOYW1lLCBjb21wb25lbnROYW1lLCBsb2NhdGlvbiwgbnVsbCwgJ1NFQ1JFVF9ET19OT1RfUEFTU19USElTX09SX1lPVV9XSUxMX0JFX0ZJUkVEJyk7XG4gICAgICAgIH0gY2F0Y2ggKGV4KSB7XG4gICAgICAgICAgZXJyb3IkMSA9IGV4O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGVycm9yJDEgJiYgIShlcnJvciQxIGluc3RhbmNlb2YgRXJyb3IpKSB7XG4gICAgICAgICAgc2V0Q3VycmVudGx5VmFsaWRhdGluZ0VsZW1lbnQoZWxlbWVudCk7XG5cbiAgICAgICAgICBlcnJvcignJXM6IHR5cGUgc3BlY2lmaWNhdGlvbiBvZiAlcycgKyAnIGAlc2AgaXMgaW52YWxpZDsgdGhlIHR5cGUgY2hlY2tlciAnICsgJ2Z1bmN0aW9uIG11c3QgcmV0dXJuIGBudWxsYCBvciBhbiBgRXJyb3JgIGJ1dCByZXR1cm5lZCBhICVzLiAnICsgJ1lvdSBtYXkgaGF2ZSBmb3Jnb3R0ZW4gdG8gcGFzcyBhbiBhcmd1bWVudCB0byB0aGUgdHlwZSBjaGVja2VyICcgKyAnY3JlYXRvciAoYXJyYXlPZiwgaW5zdGFuY2VPZiwgb2JqZWN0T2YsIG9uZU9mLCBvbmVPZlR5cGUsIGFuZCAnICsgJ3NoYXBlIGFsbCByZXF1aXJlIGFuIGFyZ3VtZW50KS4nLCBjb21wb25lbnROYW1lIHx8ICdSZWFjdCBjbGFzcycsIGxvY2F0aW9uLCB0eXBlU3BlY05hbWUsIHR5cGVvZiBlcnJvciQxKTtcblxuICAgICAgICAgIHNldEN1cnJlbnRseVZhbGlkYXRpbmdFbGVtZW50KG51bGwpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGVycm9yJDEgaW5zdGFuY2VvZiBFcnJvciAmJiAhKGVycm9yJDEubWVzc2FnZSBpbiBsb2dnZWRUeXBlRmFpbHVyZXMpKSB7XG4gICAgICAgICAgLy8gT25seSBtb25pdG9yIHRoaXMgZmFpbHVyZSBvbmNlIGJlY2F1c2UgdGhlcmUgdGVuZHMgdG8gYmUgYSBsb3Qgb2YgdGhlXG4gICAgICAgICAgLy8gc2FtZSBlcnJvci5cbiAgICAgICAgICBsb2dnZWRUeXBlRmFpbHVyZXNbZXJyb3IkMS5tZXNzYWdlXSA9IHRydWU7XG4gICAgICAgICAgc2V0Q3VycmVudGx5VmFsaWRhdGluZ0VsZW1lbnQoZWxlbWVudCk7XG5cbiAgICAgICAgICBlcnJvcignRmFpbGVkICVzIHR5cGU6ICVzJywgbG9jYXRpb24sIGVycm9yJDEubWVzc2FnZSk7XG5cbiAgICAgICAgICBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudChudWxsKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCQxKGVsZW1lbnQpIHtcbiAge1xuICAgIGlmIChlbGVtZW50KSB7XG4gICAgICB2YXIgb3duZXIgPSBlbGVtZW50Ll9vd25lcjtcbiAgICAgIHZhciBzdGFjayA9IGRlc2NyaWJlVW5rbm93bkVsZW1lbnRUeXBlRnJhbWVJbkRFVihlbGVtZW50LnR5cGUsIGVsZW1lbnQuX3NvdXJjZSwgb3duZXIgPyBvd25lci50eXBlIDogbnVsbCk7XG4gICAgICBzZXRFeHRyYVN0YWNrRnJhbWUoc3RhY2spO1xuICAgIH0gZWxzZSB7XG4gICAgICBzZXRFeHRyYVN0YWNrRnJhbWUobnVsbCk7XG4gICAgfVxuICB9XG59XG5cbnZhciBwcm9wVHlwZXNNaXNzcGVsbFdhcm5pbmdTaG93bjtcblxue1xuICBwcm9wVHlwZXNNaXNzcGVsbFdhcm5pbmdTaG93biA9IGZhbHNlO1xufVxuXG5mdW5jdGlvbiBnZXREZWNsYXJhdGlvbkVycm9yQWRkZW5kdW0oKSB7XG4gIGlmIChSZWFjdEN1cnJlbnRPd25lci5jdXJyZW50KSB7XG4gICAgdmFyIG5hbWUgPSBnZXRDb21wb25lbnROYW1lRnJvbVR5cGUoUmVhY3RDdXJyZW50T3duZXIuY3VycmVudC50eXBlKTtcblxuICAgIGlmIChuYW1lKSB7XG4gICAgICByZXR1cm4gJ1xcblxcbkNoZWNrIHRoZSByZW5kZXIgbWV0aG9kIG9mIGAnICsgbmFtZSArICdgLic7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuICcnO1xufVxuXG5mdW5jdGlvbiBnZXRTb3VyY2VJbmZvRXJyb3JBZGRlbmR1bShzb3VyY2UpIHtcbiAgaWYgKHNvdXJjZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgdmFyIGZpbGVOYW1lID0gc291cmNlLmZpbGVOYW1lLnJlcGxhY2UoL14uKltcXFxcXFwvXS8sICcnKTtcbiAgICB2YXIgbGluZU51bWJlciA9IHNvdXJjZS5saW5lTnVtYmVyO1xuICAgIHJldHVybiAnXFxuXFxuQ2hlY2sgeW91ciBjb2RlIGF0ICcgKyBmaWxlTmFtZSArICc6JyArIGxpbmVOdW1iZXIgKyAnLic7XG4gIH1cblxuICByZXR1cm4gJyc7XG59XG5cbmZ1bmN0aW9uIGdldFNvdXJjZUluZm9FcnJvckFkZGVuZHVtRm9yUHJvcHMoZWxlbWVudFByb3BzKSB7XG4gIGlmIChlbGVtZW50UHJvcHMgIT09IG51bGwgJiYgZWxlbWVudFByb3BzICE9PSB1bmRlZmluZWQpIHtcbiAgICByZXR1cm4gZ2V0U291cmNlSW5mb0Vycm9yQWRkZW5kdW0oZWxlbWVudFByb3BzLl9fc291cmNlKTtcbiAgfVxuXG4gIHJldHVybiAnJztcbn1cbi8qKlxuICogV2FybiBpZiB0aGVyZSdzIG5vIGtleSBleHBsaWNpdGx5IHNldCBvbiBkeW5hbWljIGFycmF5cyBvZiBjaGlsZHJlbiBvclxuICogb2JqZWN0IGtleXMgYXJlIG5vdCB2YWxpZC4gVGhpcyBhbGxvd3MgdXMgdG8ga2VlcCB0cmFjayBvZiBjaGlsZHJlbiBiZXR3ZWVuXG4gKiB1cGRhdGVzLlxuICovXG5cblxudmFyIG93bmVySGFzS2V5VXNlV2FybmluZyA9IHt9O1xuXG5mdW5jdGlvbiBnZXRDdXJyZW50Q29tcG9uZW50RXJyb3JJbmZvKHBhcmVudFR5cGUpIHtcbiAgdmFyIGluZm8gPSBnZXREZWNsYXJhdGlvbkVycm9yQWRkZW5kdW0oKTtcblxuICBpZiAoIWluZm8pIHtcbiAgICB2YXIgcGFyZW50TmFtZSA9IHR5cGVvZiBwYXJlbnRUeXBlID09PSAnc3RyaW5nJyA/IHBhcmVudFR5cGUgOiBwYXJlbnRUeXBlLmRpc3BsYXlOYW1lIHx8IHBhcmVudFR5cGUubmFtZTtcblxuICAgIGlmIChwYXJlbnROYW1lKSB7XG4gICAgICBpbmZvID0gXCJcXG5cXG5DaGVjayB0aGUgdG9wLWxldmVsIHJlbmRlciBjYWxsIHVzaW5nIDxcIiArIHBhcmVudE5hbWUgKyBcIj4uXCI7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGluZm87XG59XG4vKipcbiAqIFdhcm4gaWYgdGhlIGVsZW1lbnQgZG9lc24ndCBoYXZlIGFuIGV4cGxpY2l0IGtleSBhc3NpZ25lZCB0byBpdC5cbiAqIFRoaXMgZWxlbWVudCBpcyBpbiBhbiBhcnJheS4gVGhlIGFycmF5IGNvdWxkIGdyb3cgYW5kIHNocmluayBvciBiZVxuICogcmVvcmRlcmVkLiBBbGwgY2hpbGRyZW4gdGhhdCBoYXZlbid0IGFscmVhZHkgYmVlbiB2YWxpZGF0ZWQgYXJlIHJlcXVpcmVkIHRvXG4gKiBoYXZlIGEgXCJrZXlcIiBwcm9wZXJ0eSBhc3NpZ25lZCB0byBpdC4gRXJyb3Igc3RhdHVzZXMgYXJlIGNhY2hlZCBzbyBhIHdhcm5pbmdcbiAqIHdpbGwgb25seSBiZSBzaG93biBvbmNlLlxuICpcbiAqIEBpbnRlcm5hbFxuICogQHBhcmFtIHtSZWFjdEVsZW1lbnR9IGVsZW1lbnQgRWxlbWVudCB0aGF0IHJlcXVpcmVzIGEga2V5LlxuICogQHBhcmFtIHsqfSBwYXJlbnRUeXBlIGVsZW1lbnQncyBwYXJlbnQncyB0eXBlLlxuICovXG5cblxuZnVuY3Rpb24gdmFsaWRhdGVFeHBsaWNpdEtleShlbGVtZW50LCBwYXJlbnRUeXBlKSB7XG4gIGlmICghZWxlbWVudC5fc3RvcmUgfHwgZWxlbWVudC5fc3RvcmUudmFsaWRhdGVkIHx8IGVsZW1lbnQua2V5ICE9IG51bGwpIHtcbiAgICByZXR1cm47XG4gIH1cblxuICBlbGVtZW50Ll9zdG9yZS52YWxpZGF0ZWQgPSB0cnVlO1xuICB2YXIgY3VycmVudENvbXBvbmVudEVycm9ySW5mbyA9IGdldEN1cnJlbnRDb21wb25lbnRFcnJvckluZm8ocGFyZW50VHlwZSk7XG5cbiAgaWYgKG93bmVySGFzS2V5VXNlV2FybmluZ1tjdXJyZW50Q29tcG9uZW50RXJyb3JJbmZvXSkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIG93bmVySGFzS2V5VXNlV2FybmluZ1tjdXJyZW50Q29tcG9uZW50RXJyb3JJbmZvXSA9IHRydWU7IC8vIFVzdWFsbHkgdGhlIGN1cnJlbnQgb3duZXIgaXMgdGhlIG9mZmVuZGVyLCBidXQgaWYgaXQgYWNjZXB0cyBjaGlsZHJlbiBhcyBhXG4gIC8vIHByb3BlcnR5LCBpdCBtYXkgYmUgdGhlIGNyZWF0b3Igb2YgdGhlIGNoaWxkIHRoYXQncyByZXNwb25zaWJsZSBmb3JcbiAgLy8gYXNzaWduaW5nIGl0IGEga2V5LlxuXG4gIHZhciBjaGlsZE93bmVyID0gJyc7XG5cbiAgaWYgKGVsZW1lbnQgJiYgZWxlbWVudC5fb3duZXIgJiYgZWxlbWVudC5fb3duZXIgIT09IFJlYWN0Q3VycmVudE93bmVyLmN1cnJlbnQpIHtcbiAgICAvLyBHaXZlIHRoZSBjb21wb25lbnQgdGhhdCBvcmlnaW5hbGx5IGNyZWF0ZWQgdGhpcyBjaGlsZC5cbiAgICBjaGlsZE93bmVyID0gXCIgSXQgd2FzIHBhc3NlZCBhIGNoaWxkIGZyb20gXCIgKyBnZXRDb21wb25lbnROYW1lRnJvbVR5cGUoZWxlbWVudC5fb3duZXIudHlwZSkgKyBcIi5cIjtcbiAgfVxuXG4gIHtcbiAgICBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCQxKGVsZW1lbnQpO1xuXG4gICAgZXJyb3IoJ0VhY2ggY2hpbGQgaW4gYSBsaXN0IHNob3VsZCBoYXZlIGEgdW5pcXVlIFwia2V5XCIgcHJvcC4nICsgJyVzJXMgU2VlIGh0dHBzOi8vcmVhY3Rqcy5vcmcvbGluay93YXJuaW5nLWtleXMgZm9yIG1vcmUgaW5mb3JtYXRpb24uJywgY3VycmVudENvbXBvbmVudEVycm9ySW5mbywgY2hpbGRPd25lcik7XG5cbiAgICBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCQxKG51bGwpO1xuICB9XG59XG4vKipcbiAqIEVuc3VyZSB0aGF0IGV2ZXJ5IGVsZW1lbnQgZWl0aGVyIGlzIHBhc3NlZCBpbiBhIHN0YXRpYyBsb2NhdGlvbiwgaW4gYW5cbiAqIGFycmF5IHdpdGggYW4gZXhwbGljaXQga2V5cyBwcm9wZXJ0eSBkZWZpbmVkLCBvciBpbiBhbiBvYmplY3QgbGl0ZXJhbFxuICogd2l0aCB2YWxpZCBrZXkgcHJvcGVydHkuXG4gKlxuICogQGludGVybmFsXG4gKiBAcGFyYW0ge1JlYWN0Tm9kZX0gbm9kZSBTdGF0aWNhbGx5IHBhc3NlZCBjaGlsZCBvZiBhbnkgdHlwZS5cbiAqIEBwYXJhbSB7Kn0gcGFyZW50VHlwZSBub2RlJ3MgcGFyZW50J3MgdHlwZS5cbiAqL1xuXG5cbmZ1bmN0aW9uIHZhbGlkYXRlQ2hpbGRLZXlzKG5vZGUsIHBhcmVudFR5cGUpIHtcbiAgaWYgKHR5cGVvZiBub2RlICE9PSAnb2JqZWN0Jykge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGlmIChpc0FycmF5KG5vZGUpKSB7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBub2RlLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgY2hpbGQgPSBub2RlW2ldO1xuXG4gICAgICBpZiAoaXNWYWxpZEVsZW1lbnQoY2hpbGQpKSB7XG4gICAgICAgIHZhbGlkYXRlRXhwbGljaXRLZXkoY2hpbGQsIHBhcmVudFR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfSBlbHNlIGlmIChpc1ZhbGlkRWxlbWVudChub2RlKSkge1xuICAgIC8vIFRoaXMgZWxlbWVudCB3YXMgcGFzc2VkIGluIGEgdmFsaWQgbG9jYXRpb24uXG4gICAgaWYgKG5vZGUuX3N0b3JlKSB7XG4gICAgICBub2RlLl9zdG9yZS52YWxpZGF0ZWQgPSB0cnVlO1xuICAgIH1cbiAgfSBlbHNlIGlmIChub2RlKSB7XG4gICAgdmFyIGl0ZXJhdG9yRm4gPSBnZXRJdGVyYXRvckZuKG5vZGUpO1xuXG4gICAgaWYgKHR5cGVvZiBpdGVyYXRvckZuID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAvLyBFbnRyeSBpdGVyYXRvcnMgdXNlZCB0byBwcm92aWRlIGltcGxpY2l0IGtleXMsXG4gICAgICAvLyBidXQgbm93IHdlIHByaW50IGEgc2VwYXJhdGUgd2FybmluZyBmb3IgdGhlbSBsYXRlci5cbiAgICAgIGlmIChpdGVyYXRvckZuICE9PSBub2RlLmVudHJpZXMpIHtcbiAgICAgICAgdmFyIGl0ZXJhdG9yID0gaXRlcmF0b3JGbi5jYWxsKG5vZGUpO1xuICAgICAgICB2YXIgc3RlcDtcblxuICAgICAgICB3aGlsZSAoIShzdGVwID0gaXRlcmF0b3IubmV4dCgpKS5kb25lKSB7XG4gICAgICAgICAgaWYgKGlzVmFsaWRFbGVtZW50KHN0ZXAudmFsdWUpKSB7XG4gICAgICAgICAgICB2YWxpZGF0ZUV4cGxpY2l0S2V5KHN0ZXAudmFsdWUsIHBhcmVudFR5cGUpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxufVxuLyoqXG4gKiBHaXZlbiBhbiBlbGVtZW50LCB2YWxpZGF0ZSB0aGF0IGl0cyBwcm9wcyBmb2xsb3cgdGhlIHByb3BUeXBlcyBkZWZpbml0aW9uLFxuICogcHJvdmlkZWQgYnkgdGhlIHR5cGUuXG4gKlxuICogQHBhcmFtIHtSZWFjdEVsZW1lbnR9IGVsZW1lbnRcbiAqL1xuXG5cbmZ1bmN0aW9uIHZhbGlkYXRlUHJvcFR5cGVzKGVsZW1lbnQpIHtcbiAge1xuICAgIHZhciB0eXBlID0gZWxlbWVudC50eXBlO1xuXG4gICAgaWYgKHR5cGUgPT09IG51bGwgfHwgdHlwZSA9PT0gdW5kZWZpbmVkIHx8IHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHZhciBwcm9wVHlwZXM7XG5cbiAgICBpZiAodHlwZW9mIHR5cGUgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHByb3BUeXBlcyA9IHR5cGUucHJvcFR5cGVzO1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIHR5cGUgPT09ICdvYmplY3QnICYmICh0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9GT1JXQVJEX1JFRl9UWVBFIHx8IC8vIE5vdGU6IE1lbW8gb25seSBjaGVja3Mgb3V0ZXIgcHJvcHMgaGVyZS5cbiAgICAvLyBJbm5lciBwcm9wcyBhcmUgY2hlY2tlZCBpbiB0aGUgcmVjb25jaWxlci5cbiAgICB0eXBlLiQkdHlwZW9mID09PSBSRUFDVF9NRU1PX1RZUEUpKSB7XG4gICAgICBwcm9wVHlwZXMgPSB0eXBlLnByb3BUeXBlcztcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmIChwcm9wVHlwZXMpIHtcbiAgICAgIC8vIEludGVudGlvbmFsbHkgaW5zaWRlIHRvIGF2b2lkIHRyaWdnZXJpbmcgbGF6eSBpbml0aWFsaXplcnM6XG4gICAgICB2YXIgbmFtZSA9IGdldENvbXBvbmVudE5hbWVGcm9tVHlwZSh0eXBlKTtcbiAgICAgIGNoZWNrUHJvcFR5cGVzKHByb3BUeXBlcywgZWxlbWVudC5wcm9wcywgJ3Byb3AnLCBuYW1lLCBlbGVtZW50KTtcbiAgICB9IGVsc2UgaWYgKHR5cGUuUHJvcFR5cGVzICE9PSB1bmRlZmluZWQgJiYgIXByb3BUeXBlc01pc3NwZWxsV2FybmluZ1Nob3duKSB7XG4gICAgICBwcm9wVHlwZXNNaXNzcGVsbFdhcm5pbmdTaG93biA9IHRydWU7IC8vIEludGVudGlvbmFsbHkgaW5zaWRlIHRvIGF2b2lkIHRyaWdnZXJpbmcgbGF6eSBpbml0aWFsaXplcnM6XG5cbiAgICAgIHZhciBfbmFtZSA9IGdldENvbXBvbmVudE5hbWVGcm9tVHlwZSh0eXBlKTtcblxuICAgICAgZXJyb3IoJ0NvbXBvbmVudCAlcyBkZWNsYXJlZCBgUHJvcFR5cGVzYCBpbnN0ZWFkIG9mIGBwcm9wVHlwZXNgLiBEaWQgeW91IG1pc3NwZWxsIHRoZSBwcm9wZXJ0eSBhc3NpZ25tZW50PycsIF9uYW1lIHx8ICdVbmtub3duJyk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiB0eXBlLmdldERlZmF1bHRQcm9wcyA9PT0gJ2Z1bmN0aW9uJyAmJiAhdHlwZS5nZXREZWZhdWx0UHJvcHMuaXNSZWFjdENsYXNzQXBwcm92ZWQpIHtcbiAgICAgIGVycm9yKCdnZXREZWZhdWx0UHJvcHMgaXMgb25seSB1c2VkIG9uIGNsYXNzaWMgUmVhY3QuY3JlYXRlQ2xhc3MgJyArICdkZWZpbml0aW9ucy4gVXNlIGEgc3RhdGljIHByb3BlcnR5IG5hbWVkIGBkZWZhdWx0UHJvcHNgIGluc3RlYWQuJyk7XG4gICAgfVxuICB9XG59XG4vKipcbiAqIEdpdmVuIGEgZnJhZ21lbnQsIHZhbGlkYXRlIHRoYXQgaXQgY2FuIG9ubHkgYmUgcHJvdmlkZWQgd2l0aCBmcmFnbWVudCBwcm9wc1xuICogQHBhcmFtIHtSZWFjdEVsZW1lbnR9IGZyYWdtZW50XG4gKi9cblxuXG5mdW5jdGlvbiB2YWxpZGF0ZUZyYWdtZW50UHJvcHMoZnJhZ21lbnQpIHtcbiAge1xuICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMoZnJhZ21lbnQucHJvcHMpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBrZXlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIga2V5ID0ga2V5c1tpXTtcblxuICAgICAgaWYgKGtleSAhPT0gJ2NoaWxkcmVuJyAmJiBrZXkgIT09ICdrZXknKSB7XG4gICAgICAgIHNldEN1cnJlbnRseVZhbGlkYXRpbmdFbGVtZW50JDEoZnJhZ21lbnQpO1xuXG4gICAgICAgIGVycm9yKCdJbnZhbGlkIHByb3AgYCVzYCBzdXBwbGllZCB0byBgUmVhY3QuRnJhZ21lbnRgLiAnICsgJ1JlYWN0LkZyYWdtZW50IGNhbiBvbmx5IGhhdmUgYGtleWAgYW5kIGBjaGlsZHJlbmAgcHJvcHMuJywga2V5KTtcblxuICAgICAgICBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCQxKG51bGwpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoZnJhZ21lbnQucmVmICE9PSBudWxsKSB7XG4gICAgICBzZXRDdXJyZW50bHlWYWxpZGF0aW5nRWxlbWVudCQxKGZyYWdtZW50KTtcblxuICAgICAgZXJyb3IoJ0ludmFsaWQgYXR0cmlidXRlIGByZWZgIHN1cHBsaWVkIHRvIGBSZWFjdC5GcmFnbWVudGAuJyk7XG5cbiAgICAgIHNldEN1cnJlbnRseVZhbGlkYXRpbmdFbGVtZW50JDEobnVsbCk7XG4gICAgfVxuICB9XG59XG5mdW5jdGlvbiBjcmVhdGVFbGVtZW50V2l0aFZhbGlkYXRpb24odHlwZSwgcHJvcHMsIGNoaWxkcmVuKSB7XG4gIHZhciB2YWxpZFR5cGUgPSBpc1ZhbGlkRWxlbWVudFR5cGUodHlwZSk7IC8vIFdlIHdhcm4gaW4gdGhpcyBjYXNlIGJ1dCBkb24ndCB0aHJvdy4gV2UgZXhwZWN0IHRoZSBlbGVtZW50IGNyZWF0aW9uIHRvXG4gIC8vIHN1Y2NlZWQgYW5kIHRoZXJlIHdpbGwgbGlrZWx5IGJlIGVycm9ycyBpbiByZW5kZXIuXG5cbiAgaWYgKCF2YWxpZFR5cGUpIHtcbiAgICB2YXIgaW5mbyA9ICcnO1xuXG4gICAgaWYgKHR5cGUgPT09IHVuZGVmaW5lZCB8fCB0eXBlb2YgdHlwZSA9PT0gJ29iamVjdCcgJiYgdHlwZSAhPT0gbnVsbCAmJiBPYmplY3Qua2V5cyh0eXBlKS5sZW5ndGggPT09IDApIHtcbiAgICAgIGluZm8gKz0gJyBZb3UgbGlrZWx5IGZvcmdvdCB0byBleHBvcnQgeW91ciBjb21wb25lbnQgZnJvbSB0aGUgZmlsZSAnICsgXCJpdCdzIGRlZmluZWQgaW4sIG9yIHlvdSBtaWdodCBoYXZlIG1peGVkIHVwIGRlZmF1bHQgYW5kIG5hbWVkIGltcG9ydHMuXCI7XG4gICAgfVxuXG4gICAgdmFyIHNvdXJjZUluZm8gPSBnZXRTb3VyY2VJbmZvRXJyb3JBZGRlbmR1bUZvclByb3BzKHByb3BzKTtcblxuICAgIGlmIChzb3VyY2VJbmZvKSB7XG4gICAgICBpbmZvICs9IHNvdXJjZUluZm87XG4gICAgfSBlbHNlIHtcbiAgICAgIGluZm8gKz0gZ2V0RGVjbGFyYXRpb25FcnJvckFkZGVuZHVtKCk7XG4gICAgfVxuXG4gICAgdmFyIHR5cGVTdHJpbmc7XG5cbiAgICBpZiAodHlwZSA9PT0gbnVsbCkge1xuICAgICAgdHlwZVN0cmluZyA9ICdudWxsJztcbiAgICB9IGVsc2UgaWYgKGlzQXJyYXkodHlwZSkpIHtcbiAgICAgIHR5cGVTdHJpbmcgPSAnYXJyYXknO1xuICAgIH0gZWxzZSBpZiAodHlwZSAhPT0gdW5kZWZpbmVkICYmIHR5cGUuJCR0eXBlb2YgPT09IFJFQUNUX0VMRU1FTlRfVFlQRSkge1xuICAgICAgdHlwZVN0cmluZyA9IFwiPFwiICsgKGdldENvbXBvbmVudE5hbWVGcm9tVHlwZSh0eXBlLnR5cGUpIHx8ICdVbmtub3duJykgKyBcIiAvPlwiO1xuICAgICAgaW5mbyA9ICcgRGlkIHlvdSBhY2NpZGVudGFsbHkgZXhwb3J0IGEgSlNYIGxpdGVyYWwgaW5zdGVhZCBvZiBhIGNvbXBvbmVudD8nO1xuICAgIH0gZWxzZSB7XG4gICAgICB0eXBlU3RyaW5nID0gdHlwZW9mIHR5cGU7XG4gICAgfVxuXG4gICAge1xuICAgICAgZXJyb3IoJ1JlYWN0LmNyZWF0ZUVsZW1lbnQ6IHR5cGUgaXMgaW52YWxpZCAtLSBleHBlY3RlZCBhIHN0cmluZyAoZm9yICcgKyAnYnVpbHQtaW4gY29tcG9uZW50cykgb3IgYSBjbGFzcy9mdW5jdGlvbiAoZm9yIGNvbXBvc2l0ZSAnICsgJ2NvbXBvbmVudHMpIGJ1dCBnb3Q6ICVzLiVzJywgdHlwZVN0cmluZywgaW5mbyk7XG4gICAgfVxuICB9XG5cbiAgdmFyIGVsZW1lbnQgPSBjcmVhdGVFbGVtZW50LmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7IC8vIFRoZSByZXN1bHQgY2FuIGJlIG51bGxpc2ggaWYgYSBtb2NrIG9yIGEgY3VzdG9tIGZ1bmN0aW9uIGlzIHVzZWQuXG4gIC8vIFRPRE86IERyb3AgdGhpcyB3aGVuIHRoZXNlIGFyZSBubyBsb25nZXIgYWxsb3dlZCBhcyB0aGUgdHlwZSBhcmd1bWVudC5cblxuICBpZiAoZWxlbWVudCA9PSBudWxsKSB7XG4gICAgcmV0dXJuIGVsZW1lbnQ7XG4gIH0gLy8gU2tpcCBrZXkgd2FybmluZyBpZiB0aGUgdHlwZSBpc24ndCB2YWxpZCBzaW5jZSBvdXIga2V5IHZhbGlkYXRpb24gbG9naWNcbiAgLy8gZG9lc24ndCBleHBlY3QgYSBub24tc3RyaW5nL2Z1bmN0aW9uIHR5cGUgYW5kIGNhbiB0aHJvdyBjb25mdXNpbmcgZXJyb3JzLlxuICAvLyBXZSBkb24ndCB3YW50IGV4Y2VwdGlvbiBiZWhhdmlvciB0byBkaWZmZXIgYmV0d2VlbiBkZXYgYW5kIHByb2QuXG4gIC8vIChSZW5kZXJpbmcgd2lsbCB0aHJvdyB3aXRoIGEgaGVscGZ1bCBtZXNzYWdlIGFuZCBhcyBzb29uIGFzIHRoZSB0eXBlIGlzXG4gIC8vIGZpeGVkLCB0aGUga2V5IHdhcm5pbmdzIHdpbGwgYXBwZWFyLilcblxuXG4gIGlmICh2YWxpZFR5cGUpIHtcbiAgICBmb3IgKHZhciBpID0gMjsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFsaWRhdGVDaGlsZEtleXMoYXJndW1lbnRzW2ldLCB0eXBlKTtcbiAgICB9XG4gIH1cblxuICBpZiAodHlwZSA9PT0gUkVBQ1RfRlJBR01FTlRfVFlQRSkge1xuICAgIHZhbGlkYXRlRnJhZ21lbnRQcm9wcyhlbGVtZW50KTtcbiAgfSBlbHNlIHtcbiAgICB2YWxpZGF0ZVByb3BUeXBlcyhlbGVtZW50KTtcbiAgfVxuXG4gIHJldHVybiBlbGVtZW50O1xufVxudmFyIGRpZFdhcm5BYm91dERlcHJlY2F0ZWRDcmVhdGVGYWN0b3J5ID0gZmFsc2U7XG5mdW5jdGlvbiBjcmVhdGVGYWN0b3J5V2l0aFZhbGlkYXRpb24odHlwZSkge1xuICB2YXIgdmFsaWRhdGVkRmFjdG9yeSA9IGNyZWF0ZUVsZW1lbnRXaXRoVmFsaWRhdGlvbi5iaW5kKG51bGwsIHR5cGUpO1xuICB2YWxpZGF0ZWRGYWN0b3J5LnR5cGUgPSB0eXBlO1xuXG4gIHtcbiAgICBpZiAoIWRpZFdhcm5BYm91dERlcHJlY2F0ZWRDcmVhdGVGYWN0b3J5KSB7XG4gICAgICBkaWRXYXJuQWJvdXREZXByZWNhdGVkQ3JlYXRlRmFjdG9yeSA9IHRydWU7XG5cbiAgICAgIHdhcm4oJ1JlYWN0LmNyZWF0ZUZhY3RvcnkoKSBpcyBkZXByZWNhdGVkIGFuZCB3aWxsIGJlIHJlbW92ZWQgaW4gJyArICdhIGZ1dHVyZSBtYWpvciByZWxlYXNlLiBDb25zaWRlciB1c2luZyBKU1ggJyArICdvciB1c2UgUmVhY3QuY3JlYXRlRWxlbWVudCgpIGRpcmVjdGx5IGluc3RlYWQuJyk7XG4gICAgfSAvLyBMZWdhY3kgaG9vazogcmVtb3ZlIGl0XG5cblxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh2YWxpZGF0ZWRGYWN0b3J5LCAndHlwZScsIHtcbiAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHdhcm4oJ0ZhY3RvcnkudHlwZSBpcyBkZXByZWNhdGVkLiBBY2Nlc3MgdGhlIGNsYXNzIGRpcmVjdGx5ICcgKyAnYmVmb3JlIHBhc3NpbmcgaXQgdG8gY3JlYXRlRmFjdG9yeS4nKTtcblxuICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ3R5cGUnLCB7XG4gICAgICAgICAgdmFsdWU6IHR5cGVcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiB0eXBlO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIHZhbGlkYXRlZEZhY3Rvcnk7XG59XG5mdW5jdGlvbiBjbG9uZUVsZW1lbnRXaXRoVmFsaWRhdGlvbihlbGVtZW50LCBwcm9wcywgY2hpbGRyZW4pIHtcbiAgdmFyIG5ld0VsZW1lbnQgPSBjbG9uZUVsZW1lbnQuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcblxuICBmb3IgKHZhciBpID0gMjsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKykge1xuICAgIHZhbGlkYXRlQ2hpbGRLZXlzKGFyZ3VtZW50c1tpXSwgbmV3RWxlbWVudC50eXBlKTtcbiAgfVxuXG4gIHZhbGlkYXRlUHJvcFR5cGVzKG5ld0VsZW1lbnQpO1xuICByZXR1cm4gbmV3RWxlbWVudDtcbn1cblxuZnVuY3Rpb24gc3RhcnRUcmFuc2l0aW9uKHNjb3BlLCBvcHRpb25zKSB7XG4gIHZhciBwcmV2VHJhbnNpdGlvbiA9IFJlYWN0Q3VycmVudEJhdGNoQ29uZmlnLnRyYW5zaXRpb247XG4gIFJlYWN0Q3VycmVudEJhdGNoQ29uZmlnLnRyYW5zaXRpb24gPSB7fTtcbiAgdmFyIGN1cnJlbnRUcmFuc2l0aW9uID0gUmVhY3RDdXJyZW50QmF0Y2hDb25maWcudHJhbnNpdGlvbjtcblxuICB7XG4gICAgUmVhY3RDdXJyZW50QmF0Y2hDb25maWcudHJhbnNpdGlvbi5fdXBkYXRlZEZpYmVycyA9IG5ldyBTZXQoKTtcbiAgfVxuXG4gIHRyeSB7XG4gICAgc2NvcGUoKTtcbiAgfSBmaW5hbGx5IHtcbiAgICBSZWFjdEN1cnJlbnRCYXRjaENvbmZpZy50cmFuc2l0aW9uID0gcHJldlRyYW5zaXRpb247XG5cbiAgICB7XG4gICAgICBpZiAocHJldlRyYW5zaXRpb24gPT09IG51bGwgJiYgY3VycmVudFRyYW5zaXRpb24uX3VwZGF0ZWRGaWJlcnMpIHtcbiAgICAgICAgdmFyIHVwZGF0ZWRGaWJlcnNDb3VudCA9IGN1cnJlbnRUcmFuc2l0aW9uLl91cGRhdGVkRmliZXJzLnNpemU7XG5cbiAgICAgICAgaWYgKHVwZGF0ZWRGaWJlcnNDb3VudCA+IDEwKSB7XG4gICAgICAgICAgd2FybignRGV0ZWN0ZWQgYSBsYXJnZSBudW1iZXIgb2YgdXBkYXRlcyBpbnNpZGUgc3RhcnRUcmFuc2l0aW9uLiAnICsgJ0lmIHRoaXMgaXMgZHVlIHRvIGEgc3Vic2NyaXB0aW9uIHBsZWFzZSByZS13cml0ZSBpdCB0byB1c2UgUmVhY3QgcHJvdmlkZWQgaG9va3MuICcgKyAnT3RoZXJ3aXNlIGNvbmN1cnJlbnQgbW9kZSBndWFyYW50ZWVzIGFyZSBvZmYgdGhlIHRhYmxlLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgY3VycmVudFRyYW5zaXRpb24uX3VwZGF0ZWRGaWJlcnMuY2xlYXIoKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxudmFyIGRpZFdhcm5BYm91dE1lc3NhZ2VDaGFubmVsID0gZmFsc2U7XG52YXIgZW5xdWV1ZVRhc2tJbXBsID0gbnVsbDtcbmZ1bmN0aW9uIGVucXVldWVUYXNrKHRhc2spIHtcbiAgaWYgKGVucXVldWVUYXNrSW1wbCA9PT0gbnVsbCkge1xuICAgIHRyeSB7XG4gICAgICAvLyByZWFkIHJlcXVpcmUgb2ZmIHRoZSBtb2R1bGUgb2JqZWN0IHRvIGdldCBhcm91bmQgdGhlIGJ1bmRsZXJzLlxuICAgICAgLy8gd2UgZG9uJ3Qgd2FudCB0aGVtIHRvIGRldGVjdCBhIHJlcXVpcmUgYW5kIGJ1bmRsZSBhIE5vZGUgcG9seWZpbGwuXG4gICAgICB2YXIgcmVxdWlyZVN0cmluZyA9ICgncmVxdWlyZScgKyBNYXRoLnJhbmRvbSgpKS5zbGljZSgwLCA3KTtcbiAgICAgIHZhciBub2RlUmVxdWlyZSA9IG1vZHVsZSAmJiBtb2R1bGVbcmVxdWlyZVN0cmluZ107IC8vIGFzc3VtaW5nIHdlJ3JlIGluIG5vZGUsIGxldCdzIHRyeSB0byBnZXQgbm9kZSdzXG4gICAgICAvLyB2ZXJzaW9uIG9mIHNldEltbWVkaWF0ZSwgYnlwYXNzaW5nIGZha2UgdGltZXJzIGlmIGFueS5cblxuICAgICAgZW5xdWV1ZVRhc2tJbXBsID0gbm9kZVJlcXVpcmUuY2FsbChtb2R1bGUsICd0aW1lcnMnKS5zZXRJbW1lZGlhdGU7XG4gICAgfSBjYXRjaCAoX2Vycikge1xuICAgICAgLy8gd2UncmUgaW4gYSBicm93c2VyXG4gICAgICAvLyB3ZSBjYW4ndCB1c2UgcmVndWxhciB0aW1lcnMgYmVjYXVzZSB0aGV5IG1heSBzdGlsbCBiZSBmYWtlZFxuICAgICAgLy8gc28gd2UgdHJ5IE1lc3NhZ2VDaGFubmVsK3Bvc3RNZXNzYWdlIGluc3RlYWRcbiAgICAgIGVucXVldWVUYXNrSW1wbCA9IGZ1bmN0aW9uIChjYWxsYmFjaykge1xuICAgICAgICB7XG4gICAgICAgICAgaWYgKGRpZFdhcm5BYm91dE1lc3NhZ2VDaGFubmVsID09PSBmYWxzZSkge1xuICAgICAgICAgICAgZGlkV2FybkFib3V0TWVzc2FnZUNoYW5uZWwgPSB0cnVlO1xuXG4gICAgICAgICAgICBpZiAodHlwZW9mIE1lc3NhZ2VDaGFubmVsID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgICBlcnJvcignVGhpcyBicm93c2VyIGRvZXMgbm90IGhhdmUgYSBNZXNzYWdlQ2hhbm5lbCBpbXBsZW1lbnRhdGlvbiwgJyArICdzbyBlbnF1ZXVpbmcgdGFza3MgdmlhIGF3YWl0IGFjdChhc3luYyAoKSA9PiAuLi4pIHdpbGwgZmFpbC4gJyArICdQbGVhc2UgZmlsZSBhbiBpc3N1ZSBhdCBodHRwczovL2dpdGh1Yi5jb20vZmFjZWJvb2svcmVhY3QvaXNzdWVzICcgKyAnaWYgeW91IGVuY291bnRlciB0aGlzIHdhcm5pbmcuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgdmFyIGNoYW5uZWwgPSBuZXcgTWVzc2FnZUNoYW5uZWwoKTtcbiAgICAgICAgY2hhbm5lbC5wb3J0MS5vbm1lc3NhZ2UgPSBjYWxsYmFjaztcbiAgICAgICAgY2hhbm5lbC5wb3J0Mi5wb3N0TWVzc2FnZSh1bmRlZmluZWQpO1xuICAgICAgfTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZW5xdWV1ZVRhc2tJbXBsKHRhc2spO1xufVxuXG52YXIgYWN0U2NvcGVEZXB0aCA9IDA7XG52YXIgZGlkV2Fybk5vQXdhaXRBY3QgPSBmYWxzZTtcbmZ1bmN0aW9uIGFjdChjYWxsYmFjaykge1xuICB7XG4gICAgLy8gYGFjdGAgY2FsbHMgY2FuIGJlIG5lc3RlZCwgc28gd2UgdHJhY2sgdGhlIGRlcHRoLiBUaGlzIHJlcHJlc2VudHMgdGhlXG4gICAgLy8gbnVtYmVyIG9mIGBhY3RgIHNjb3BlcyBvbiB0aGUgc3RhY2suXG4gICAgdmFyIHByZXZBY3RTY29wZURlcHRoID0gYWN0U2NvcGVEZXB0aDtcbiAgICBhY3RTY29wZURlcHRoKys7XG5cbiAgICBpZiAoUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudCA9PT0gbnVsbCkge1xuICAgICAgLy8gVGhpcyBpcyB0aGUgb3V0ZXJtb3N0IGBhY3RgIHNjb3BlLiBJbml0aWFsaXplIHRoZSBxdWV1ZS4gVGhlIHJlY29uY2lsZXJcbiAgICAgIC8vIHdpbGwgZGV0ZWN0IHRoZSBxdWV1ZSBhbmQgdXNlIGl0IGluc3RlYWQgb2YgU2NoZWR1bGVyLlxuICAgICAgUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudCA9IFtdO1xuICAgIH1cblxuICAgIHZhciBwcmV2SXNCYXRjaGluZ0xlZ2FjeSA9IFJlYWN0Q3VycmVudEFjdFF1ZXVlLmlzQmF0Y2hpbmdMZWdhY3k7XG4gICAgdmFyIHJlc3VsdDtcblxuICAgIHRyeSB7XG4gICAgICAvLyBVc2VkIHRvIHJlcHJvZHVjZSBiZWhhdmlvciBvZiBgYmF0Y2hlZFVwZGF0ZXNgIGluIGxlZ2FjeSBtb2RlLiBPbmx5XG4gICAgICAvLyBzZXQgdG8gYHRydWVgIHdoaWxlIHRoZSBnaXZlbiBjYWxsYmFjayBpcyBleGVjdXRlZCwgbm90IGZvciB1cGRhdGVzXG4gICAgICAvLyB0cmlnZ2VyZWQgZHVyaW5nIGFuIGFzeW5jIGV2ZW50LCBiZWNhdXNlIHRoaXMgaXMgaG93IHRoZSBsZWdhY3lcbiAgICAgIC8vIGltcGxlbWVudGF0aW9uIG9mIGBhY3RgIGJlaGF2ZWQuXG4gICAgICBSZWFjdEN1cnJlbnRBY3RRdWV1ZS5pc0JhdGNoaW5nTGVnYWN5ID0gdHJ1ZTtcbiAgICAgIHJlc3VsdCA9IGNhbGxiYWNrKCk7IC8vIFJlcGxpY2F0ZSBiZWhhdmlvciBvZiBvcmlnaW5hbCBgYWN0YCBpbXBsZW1lbnRhdGlvbiBpbiBsZWdhY3kgbW9kZSxcbiAgICAgIC8vIHdoaWNoIGZsdXNoZWQgdXBkYXRlcyBpbW1lZGlhdGVseSBhZnRlciB0aGUgc2NvcGUgZnVuY3Rpb24gZXhpdHMsIGV2ZW5cbiAgICAgIC8vIGlmIGl0J3MgYW4gYXN5bmMgZnVuY3Rpb24uXG5cbiAgICAgIGlmICghcHJldklzQmF0Y2hpbmdMZWdhY3kgJiYgUmVhY3RDdXJyZW50QWN0UXVldWUuZGlkU2NoZWR1bGVMZWdhY3lVcGRhdGUpIHtcbiAgICAgICAgdmFyIHF1ZXVlID0gUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudDtcblxuICAgICAgICBpZiAocXVldWUgIT09IG51bGwpIHtcbiAgICAgICAgICBSZWFjdEN1cnJlbnRBY3RRdWV1ZS5kaWRTY2hlZHVsZUxlZ2FjeVVwZGF0ZSA9IGZhbHNlO1xuICAgICAgICAgIGZsdXNoQWN0UXVldWUocXVldWUpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHBvcEFjdFNjb3BlKHByZXZBY3RTY29wZURlcHRoKTtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH0gZmluYWxseSB7XG4gICAgICBSZWFjdEN1cnJlbnRBY3RRdWV1ZS5pc0JhdGNoaW5nTGVnYWN5ID0gcHJldklzQmF0Y2hpbmdMZWdhY3k7XG4gICAgfVxuXG4gICAgaWYgKHJlc3VsdCAhPT0gbnVsbCAmJiB0eXBlb2YgcmVzdWx0ID09PSAnb2JqZWN0JyAmJiB0eXBlb2YgcmVzdWx0LnRoZW4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHZhciB0aGVuYWJsZVJlc3VsdCA9IHJlc3VsdDsgLy8gVGhlIGNhbGxiYWNrIGlzIGFuIGFzeW5jIGZ1bmN0aW9uIChpLmUuIHJldHVybmVkIGEgcHJvbWlzZSkuIFdhaXRcbiAgICAgIC8vIGZvciBpdCB0byByZXNvbHZlIGJlZm9yZSBleGl0aW5nIHRoZSBjdXJyZW50IHNjb3BlLlxuXG4gICAgICB2YXIgd2FzQXdhaXRlZCA9IGZhbHNlO1xuICAgICAgdmFyIHRoZW5hYmxlID0ge1xuICAgICAgICB0aGVuOiBmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgd2FzQXdhaXRlZCA9IHRydWU7XG4gICAgICAgICAgdGhlbmFibGVSZXN1bHQudGhlbihmdW5jdGlvbiAocmV0dXJuVmFsdWUpIHtcbiAgICAgICAgICAgIHBvcEFjdFNjb3BlKHByZXZBY3RTY29wZURlcHRoKTtcblxuICAgICAgICAgICAgaWYgKGFjdFNjb3BlRGVwdGggPT09IDApIHtcbiAgICAgICAgICAgICAgLy8gV2UndmUgZXhpdGVkIHRoZSBvdXRlcm1vc3QgYWN0IHNjb3BlLiBSZWN1cnNpdmVseSBmbHVzaCB0aGVcbiAgICAgICAgICAgICAgLy8gcXVldWUgdW50aWwgdGhlcmUncyBubyByZW1haW5pbmcgd29yay5cbiAgICAgICAgICAgICAgcmVjdXJzaXZlbHlGbHVzaEFzeW5jQWN0V29yayhyZXR1cm5WYWx1ZSwgcmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJlc29sdmUocmV0dXJuVmFsdWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICAgICAgLy8gVGhlIGNhbGxiYWNrIHRocmV3IGFuIGVycm9yLlxuICAgICAgICAgICAgcG9wQWN0U2NvcGUocHJldkFjdFNjb3BlRGVwdGgpO1xuICAgICAgICAgICAgcmVqZWN0KGVycm9yKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAge1xuICAgICAgICBpZiAoIWRpZFdhcm5Ob0F3YWl0QWN0ICYmIHR5cGVvZiBQcm9taXNlICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlZlxuICAgICAgICAgIFByb21pc2UucmVzb2x2ZSgpLnRoZW4oZnVuY3Rpb24gKCkge30pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgaWYgKCF3YXNBd2FpdGVkKSB7XG4gICAgICAgICAgICAgIGRpZFdhcm5Ob0F3YWl0QWN0ID0gdHJ1ZTtcblxuICAgICAgICAgICAgICBlcnJvcignWW91IGNhbGxlZCBhY3QoYXN5bmMgKCkgPT4gLi4uKSB3aXRob3V0IGF3YWl0LiAnICsgJ1RoaXMgY291bGQgbGVhZCB0byB1bmV4cGVjdGVkIHRlc3RpbmcgYmVoYXZpb3VyLCAnICsgJ2ludGVybGVhdmluZyBtdWx0aXBsZSBhY3QgY2FsbHMgYW5kIG1peGluZyB0aGVpciAnICsgJ3Njb3Blcy4gJyArICdZb3Ugc2hvdWxkIC0gYXdhaXQgYWN0KGFzeW5jICgpID0+IC4uLik7Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHRoZW5hYmxlO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgcmV0dXJuVmFsdWUgPSByZXN1bHQ7IC8vIFRoZSBjYWxsYmFjayBpcyBub3QgYW4gYXN5bmMgZnVuY3Rpb24uIEV4aXQgdGhlIGN1cnJlbnQgc2NvcGVcbiAgICAgIC8vIGltbWVkaWF0ZWx5LCB3aXRob3V0IGF3YWl0aW5nLlxuXG4gICAgICBwb3BBY3RTY29wZShwcmV2QWN0U2NvcGVEZXB0aCk7XG5cbiAgICAgIGlmIChhY3RTY29wZURlcHRoID09PSAwKSB7XG4gICAgICAgIC8vIEV4aXRpbmcgdGhlIG91dGVybW9zdCBhY3Qgc2NvcGUuIEZsdXNoIHRoZSBxdWV1ZS5cbiAgICAgICAgdmFyIF9xdWV1ZSA9IFJlYWN0Q3VycmVudEFjdFF1ZXVlLmN1cnJlbnQ7XG5cbiAgICAgICAgaWYgKF9xdWV1ZSAhPT0gbnVsbCkge1xuICAgICAgICAgIGZsdXNoQWN0UXVldWUoX3F1ZXVlKTtcbiAgICAgICAgICBSZWFjdEN1cnJlbnRBY3RRdWV1ZS5jdXJyZW50ID0gbnVsbDtcbiAgICAgICAgfSAvLyBSZXR1cm4gYSB0aGVuYWJsZS4gSWYgdGhlIHVzZXIgYXdhaXRzIGl0LCB3ZSdsbCBmbHVzaCBhZ2FpbiBpblxuICAgICAgICAvLyBjYXNlIGFkZGl0aW9uYWwgd29yayB3YXMgc2NoZWR1bGVkIGJ5IGEgbWljcm90YXNrLlxuXG5cbiAgICAgICAgdmFyIF90aGVuYWJsZSA9IHtcbiAgICAgICAgICB0aGVuOiBmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICAvLyBDb25maXJtIHdlIGhhdmVuJ3QgcmUtZW50ZXJlZCBhbm90aGVyIGBhY3RgIHNjb3BlLCBpbiBjYXNlXG4gICAgICAgICAgICAvLyB0aGUgdXNlciBkb2VzIHNvbWV0aGluZyB3ZWlyZCBsaWtlIGF3YWl0IHRoZSB0aGVuYWJsZVxuICAgICAgICAgICAgLy8gbXVsdGlwbGUgdGltZXMuXG4gICAgICAgICAgICBpZiAoUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudCA9PT0gbnVsbCkge1xuICAgICAgICAgICAgICAvLyBSZWN1cnNpdmVseSBmbHVzaCB0aGUgcXVldWUgdW50aWwgdGhlcmUncyBubyByZW1haW5pbmcgd29yay5cbiAgICAgICAgICAgICAgUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudCA9IFtdO1xuICAgICAgICAgICAgICByZWN1cnNpdmVseUZsdXNoQXN5bmNBY3RXb3JrKHJldHVyblZhbHVlLCByZXNvbHZlLCByZWplY3QpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmVzb2x2ZShyZXR1cm5WYWx1ZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4gX3RoZW5hYmxlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gU2luY2Ugd2UncmUgaW5zaWRlIGEgbmVzdGVkIGBhY3RgIHNjb3BlLCB0aGUgcmV0dXJuZWQgdGhlbmFibGVcbiAgICAgICAgLy8gaW1tZWRpYXRlbHkgcmVzb2x2ZXMuIFRoZSBvdXRlciBzY29wZSB3aWxsIGZsdXNoIHRoZSBxdWV1ZS5cbiAgICAgICAgdmFyIF90aGVuYWJsZTIgPSB7XG4gICAgICAgICAgdGhlbjogZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgcmVzb2x2ZShyZXR1cm5WYWx1ZSk7XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4gX3RoZW5hYmxlMjtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gcG9wQWN0U2NvcGUocHJldkFjdFNjb3BlRGVwdGgpIHtcbiAge1xuICAgIGlmIChwcmV2QWN0U2NvcGVEZXB0aCAhPT0gYWN0U2NvcGVEZXB0aCAtIDEpIHtcbiAgICAgIGVycm9yKCdZb3Ugc2VlbSB0byBoYXZlIG92ZXJsYXBwaW5nIGFjdCgpIGNhbGxzLCB0aGlzIGlzIG5vdCBzdXBwb3J0ZWQuICcgKyAnQmUgc3VyZSB0byBhd2FpdCBwcmV2aW91cyBhY3QoKSBjYWxscyBiZWZvcmUgbWFraW5nIGEgbmV3IG9uZS4gJyk7XG4gICAgfVxuXG4gICAgYWN0U2NvcGVEZXB0aCA9IHByZXZBY3RTY29wZURlcHRoO1xuICB9XG59XG5cbmZ1bmN0aW9uIHJlY3Vyc2l2ZWx5Rmx1c2hBc3luY0FjdFdvcmsocmV0dXJuVmFsdWUsIHJlc29sdmUsIHJlamVjdCkge1xuICB7XG4gICAgdmFyIHF1ZXVlID0gUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudDtcblxuICAgIGlmIChxdWV1ZSAhPT0gbnVsbCkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgZmx1c2hBY3RRdWV1ZShxdWV1ZSk7XG4gICAgICAgIGVucXVldWVUYXNrKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAocXVldWUubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgICAvLyBObyBhZGRpdGlvbmFsIHdvcmsgd2FzIHNjaGVkdWxlZC4gRmluaXNoLlxuICAgICAgICAgICAgUmVhY3RDdXJyZW50QWN0UXVldWUuY3VycmVudCA9IG51bGw7XG4gICAgICAgICAgICByZXNvbHZlKHJldHVyblZhbHVlKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gS2VlcCBmbHVzaGluZyB3b3JrIHVudGlsIHRoZXJlJ3Mgbm9uZSBsZWZ0LlxuICAgICAgICAgICAgcmVjdXJzaXZlbHlGbHVzaEFzeW5jQWN0V29yayhyZXR1cm5WYWx1ZSwgcmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgcmVqZWN0KGVycm9yKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgcmVzb2x2ZShyZXR1cm5WYWx1ZSk7XG4gICAgfVxuICB9XG59XG5cbnZhciBpc0ZsdXNoaW5nID0gZmFsc2U7XG5cbmZ1bmN0aW9uIGZsdXNoQWN0UXVldWUocXVldWUpIHtcbiAge1xuICAgIGlmICghaXNGbHVzaGluZykge1xuICAgICAgLy8gUHJldmVudCByZS1lbnRyYW5jZS5cbiAgICAgIGlzRmx1c2hpbmcgPSB0cnVlO1xuICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICB0cnkge1xuICAgICAgICBmb3IgKDsgaSA8IHF1ZXVlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgdmFyIGNhbGxiYWNrID0gcXVldWVbaV07XG5cbiAgICAgICAgICBkbyB7XG4gICAgICAgICAgICBjYWxsYmFjayA9IGNhbGxiYWNrKHRydWUpO1xuICAgICAgICAgIH0gd2hpbGUgKGNhbGxiYWNrICE9PSBudWxsKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHF1ZXVlLmxlbmd0aCA9IDA7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAvLyBJZiBzb21ldGhpbmcgdGhyb3dzLCBsZWF2ZSB0aGUgcmVtYWluaW5nIGNhbGxiYWNrcyBvbiB0aGUgcXVldWUuXG4gICAgICAgIHF1ZXVlID0gcXVldWUuc2xpY2UoaSArIDEpO1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIGlzRmx1c2hpbmcgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxudmFyIGNyZWF0ZUVsZW1lbnQkMSA9ICBjcmVhdGVFbGVtZW50V2l0aFZhbGlkYXRpb24gO1xudmFyIGNsb25lRWxlbWVudCQxID0gIGNsb25lRWxlbWVudFdpdGhWYWxpZGF0aW9uIDtcbnZhciBjcmVhdGVGYWN0b3J5ID0gIGNyZWF0ZUZhY3RvcnlXaXRoVmFsaWRhdGlvbiA7XG52YXIgQ2hpbGRyZW4gPSB7XG4gIG1hcDogbWFwQ2hpbGRyZW4sXG4gIGZvckVhY2g6IGZvckVhY2hDaGlsZHJlbixcbiAgY291bnQ6IGNvdW50Q2hpbGRyZW4sXG4gIHRvQXJyYXk6IHRvQXJyYXksXG4gIG9ubHk6IG9ubHlDaGlsZFxufTtcblxuZXhwb3J0cy5DaGlsZHJlbiA9IENoaWxkcmVuO1xuZXhwb3J0cy5Db21wb25lbnQgPSBDb21wb25lbnQ7XG5leHBvcnRzLkZyYWdtZW50ID0gUkVBQ1RfRlJBR01FTlRfVFlQRTtcbmV4cG9ydHMuUHJvZmlsZXIgPSBSRUFDVF9QUk9GSUxFUl9UWVBFO1xuZXhwb3J0cy5QdXJlQ29tcG9uZW50ID0gUHVyZUNvbXBvbmVudDtcbmV4cG9ydHMuU3RyaWN0TW9kZSA9IFJFQUNUX1NUUklDVF9NT0RFX1RZUEU7XG5leHBvcnRzLlN1c3BlbnNlID0gUkVBQ1RfU1VTUEVOU0VfVFlQRTtcbmV4cG9ydHMuX19TRUNSRVRfSU5URVJOQUxTX0RPX05PVF9VU0VfT1JfWU9VX1dJTExfQkVfRklSRUQgPSBSZWFjdFNoYXJlZEludGVybmFscztcbmV4cG9ydHMuY2xvbmVFbGVtZW50ID0gY2xvbmVFbGVtZW50JDE7XG5leHBvcnRzLmNyZWF0ZUNvbnRleHQgPSBjcmVhdGVDb250ZXh0O1xuZXhwb3J0cy5jcmVhdGVFbGVtZW50ID0gY3JlYXRlRWxlbWVudCQxO1xuZXhwb3J0cy5jcmVhdGVGYWN0b3J5ID0gY3JlYXRlRmFjdG9yeTtcbmV4cG9ydHMuY3JlYXRlUmVmID0gY3JlYXRlUmVmO1xuZXhwb3J0cy5mb3J3YXJkUmVmID0gZm9yd2FyZFJlZjtcbmV4cG9ydHMuaXNWYWxpZEVsZW1lbnQgPSBpc1ZhbGlkRWxlbWVudDtcbmV4cG9ydHMubGF6eSA9IGxhenk7XG5leHBvcnRzLm1lbW8gPSBtZW1vO1xuZXhwb3J0cy5zdGFydFRyYW5zaXRpb24gPSBzdGFydFRyYW5zaXRpb247XG5leHBvcnRzLnVuc3RhYmxlX2FjdCA9IGFjdDtcbmV4cG9ydHMudXNlQ2FsbGJhY2sgPSB1c2VDYWxsYmFjaztcbmV4cG9ydHMudXNlQ29udGV4dCA9IHVzZUNvbnRleHQ7XG5leHBvcnRzLnVzZURlYnVnVmFsdWUgPSB1c2VEZWJ1Z1ZhbHVlO1xuZXhwb3J0cy51c2VEZWZlcnJlZFZhbHVlID0gdXNlRGVmZXJyZWRWYWx1ZTtcbmV4cG9ydHMudXNlRWZmZWN0ID0gdXNlRWZmZWN0O1xuZXhwb3J0cy51c2VJZCA9IHVzZUlkO1xuZXhwb3J0cy51c2VJbXBlcmF0aXZlSGFuZGxlID0gdXNlSW1wZXJhdGl2ZUhhbmRsZTtcbmV4cG9ydHMudXNlSW5zZXJ0aW9uRWZmZWN0ID0gdXNlSW5zZXJ0aW9uRWZmZWN0O1xuZXhwb3J0cy51c2VMYXlvdXRFZmZlY3QgPSB1c2VMYXlvdXRFZmZlY3Q7XG5leHBvcnRzLnVzZU1lbW8gPSB1c2VNZW1vO1xuZXhwb3J0cy51c2VSZWR1Y2VyID0gdXNlUmVkdWNlcjtcbmV4cG9ydHMudXNlUmVmID0gdXNlUmVmO1xuZXhwb3J0cy51c2VTdGF0ZSA9IHVzZVN0YXRlO1xuZXhwb3J0cy51c2VTeW5jRXh0ZXJuYWxTdG9yZSA9IHVzZVN5bmNFeHRlcm5hbFN0b3JlO1xuZXhwb3J0cy51c2VUcmFuc2l0aW9uID0gdXNlVHJhbnNpdGlvbjtcbmV4cG9ydHMudmVyc2lvbiA9IFJlYWN0VmVyc2lvbjtcbiAgICAgICAgICAvKiBnbG9iYWwgX19SRUFDVF9ERVZUT09MU19HTE9CQUxfSE9PS19fICovXG5pZiAoXG4gIHR5cGVvZiBfX1JFQUNUX0RFVlRPT0xTX0dMT0JBTF9IT09LX18gIT09ICd1bmRlZmluZWQnICYmXG4gIHR5cGVvZiBfX1JFQUNUX0RFVlRPT0xTX0dMT0JBTF9IT09LX18ucmVnaXN0ZXJJbnRlcm5hbE1vZHVsZVN0b3AgPT09XG4gICAgJ2Z1bmN0aW9uJ1xuKSB7XG4gIF9fUkVBQ1RfREVWVE9PTFNfR0xPQkFMX0hPT0tfXy5yZWdpc3RlckludGVybmFsTW9kdWxlU3RvcChuZXcgRXJyb3IoKSk7XG59XG4gICAgICAgIFxuICB9KSgpO1xufVxuIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUEsWUFBWTs7QUFFWixJQUFJQSxPQUFPLENBQUNDLEdBQUcsQ0FBQ0MsUUFBUSxLQUFLLFlBQVksRUFBRTtFQUN6QyxDQUFDLFlBQVc7SUFFSixZQUFZOztJQUV0QjtJQUNBLElBQ0UsT0FBT0MsOEJBQThCLEtBQUssV0FBVyxJQUNyRCxPQUFPQSw4QkFBOEIsQ0FBQ0MsMkJBQTJCLEtBQy9ELFVBQVUsRUFDWjtNQUNBRCw4QkFBOEIsQ0FBQ0MsMkJBQTJCLENBQUMsSUFBSUMsS0FBSyxFQUFFLENBQUM7SUFDekU7SUFDVSxJQUFJQyxZQUFZLEdBQUcsUUFBUTs7SUFFckM7SUFDQTtJQUNBO0lBQ0E7SUFDQSxJQUFJQyxrQkFBa0IsR0FBR0MsTUFBTSxDQUFDQyxHQUFHLENBQUMsZUFBZSxDQUFDO0lBQ3BELElBQUlDLGlCQUFpQixHQUFHRixNQUFNLENBQUNDLEdBQUcsQ0FBQyxjQUFjLENBQUM7SUFDbEQsSUFBSUUsbUJBQW1CLEdBQUdILE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLGdCQUFnQixDQUFDO0lBQ3RELElBQUlHLHNCQUFzQixHQUFHSixNQUFNLENBQUNDLEdBQUcsQ0FBQyxtQkFBbUIsQ0FBQztJQUM1RCxJ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
}).call(this,require("Xp6JUx"))
},{"Xp6JUx":2}],13:[function(require,module,exports){
/**
 * @license React
 * react.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
'use strict';

var l = Symbol.for("react.element"),
  n = Symbol.for("react.portal"),
  p = Symbol.for("react.fragment"),
  q = Symbol.for("react.strict_mode"),
  r = Symbol.for("react.profiler"),
  t = Symbol.for("react.provider"),
  u = Symbol.for("react.context"),
  v = Symbol.for("react.forward_ref"),
  w = Symbol.for("react.suspense"),
  x = Symbol.for("react.memo"),
  y = Symbol.for("react.lazy"),
  z = Symbol.iterator;
function A(a) {
  if (null === a || "object" !== typeof a) return null;
  a = z && a[z] || a["@@iterator"];
  return "function" === typeof a ? a : null;
}
var B = {
    isMounted: function () {
      return !1;
    },
    enqueueForceUpdate: function () {},
    enqueueReplaceState: function () {},
    enqueueSetState: function () {}
  },
  C = Object.assign,
  D = {};
function E(a, b, e) {
  this.props = a;
  this.context = b;
  this.refs = D;
  this.updater = e || B;
}
E.prototype.isReactComponent = {};
E.prototype.setState = function (a, b) {
  if ("object" !== typeof a && "function" !== typeof a && null != a) throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");
  this.updater.enqueueSetState(this, a, b, "setState");
};
E.prototype.forceUpdate = function (a) {
  this.updater.enqueueForceUpdate(this, a, "forceUpdate");
};
function F() {}
F.prototype = E.prototype;
function G(a, b, e) {
  this.props = a;
  this.context = b;
  this.refs = D;
  this.updater = e || B;
}
var H = G.prototype = new F();
H.constructor = G;
C(H, E.prototype);
H.isPureReactComponent = !0;
var I = Array.isArray,
  J = Object.prototype.hasOwnProperty,
  K = {
    current: null
  },
  L = {
    key: !0,
    ref: !0,
    __self: !0,
    __source: !0
  };
function M(a, b, e) {
  var d,
    c = {},
    k = null,
    h = null;
  if (null != b) for (d in void 0 !== b.ref && (h = b.ref), void 0 !== b.key && (k = "" + b.key), b) J.call(b, d) && !L.hasOwnProperty(d) && (c[d] = b[d]);
  var g = arguments.length - 2;
  if (1 === g) c.children = e;else if (1 < g) {
    for (var f = Array(g), m = 0; m < g; m++) f[m] = arguments[m + 2];
    c.children = f;
  }
  if (a && a.defaultProps) for (d in g = a.defaultProps, g) void 0 === c[d] && (c[d] = g[d]);
  return {
    $$typeof: l,
    type: a,
    key: k,
    ref: h,
    props: c,
    _owner: K.current
  };
}
function N(a, b) {
  return {
    $$typeof: l,
    type: a.type,
    key: b,
    ref: a.ref,
    props: a.props,
    _owner: a._owner
  };
}
function O(a) {
  return "object" === typeof a && null !== a && a.$$typeof === l;
}
function escape(a) {
  var b = {
    "=": "=0",
    ":": "=2"
  };
  return "$" + a.replace(/[=:]/g, function (a) {
    return b[a];
  });
}
var P = /\/+/g;
function Q(a, b) {
  return "object" === typeof a && null !== a && null != a.key ? escape("" + a.key) : b.toString(36);
}
function R(a, b, e, d, c) {
  var k = typeof a;
  if ("undefined" === k || "boolean" === k) a = null;
  var h = !1;
  if (null === a) h = !0;else switch (k) {
    case "string":
    case "number":
      h = !0;
      break;
    case "object":
      switch (a.$$typeof) {
        case l:
        case n:
          h = !0;
      }
  }
  if (h) return h = a, c = c(h), a = "" === d ? "." + Q(h, 0) : d, I(c) ? (e = "", null != a && (e = a.replace(P, "$&/") + "/"), R(c, b, e, "", function (a) {
    return a;
  })) : null != c && (O(c) && (c = N(c, e + (!c.key || h && h.key === c.key ? "" : ("" + c.key).replace(P, "$&/") + "/") + a)), b.push(c)), 1;
  h = 0;
  d = "" === d ? "." : d + ":";
  if (I(a)) for (var g = 0; g < a.length; g++) {
    k = a[g];
    var f = d + Q(k, g);
    h += R(k, b, e, f, c);
  } else if (f = A(a), "function" === typeof f) for (a = f.call(a), g = 0; !(k = a.next()).done;) k = k.value, f = d + Q(k, g++), h += R(k, b, e, f, c);else if ("object" === k) throw b = String(a), Error("Objects are not valid as a React child (found: " + ("[object Object]" === b ? "object with keys {" + Object.keys(a).join(", ") + "}" : b) + "). If you meant to render a collection of children, use an array instead.");
  return h;
}
function S(a, b, e) {
  if (null == a) return a;
  var d = [],
    c = 0;
  R(a, d, "", "", function (a) {
    return b.call(e, a, c++);
  });
  return d;
}
function T(a) {
  if (-1 === a._status) {
    var b = a._result;
    b = b();
    b.then(function (b) {
      if (0 === a._status || -1 === a._status) a._status = 1, a._result = b;
    }, function (b) {
      if (0 === a._status || -1 === a._status) a._status = 2, a._result = b;
    });
    -1 === a._status && (a._status = 0, a._result = b);
  }
  if (1 === a._status) return a._result.default;
  throw a._result;
}
var U = {
    current: null
  },
  V = {
    transition: null
  },
  W = {
    ReactCurrentDispatcher: U,
    ReactCurrentBatchConfig: V,
    ReactCurrentOwner: K
  };
exports.Children = {
  map: S,
  forEach: function (a, b, e) {
    S(a, function () {
      b.apply(this, arguments);
    }, e);
  },
  count: function (a) {
    var b = 0;
    S(a, function () {
      b++;
    });
    return b;
  },
  toArray: function (a) {
    return S(a, function (a) {
      return a;
    }) || [];
  },
  only: function (a) {
    if (!O(a)) throw Error("React.Children.only expected to receive a single React element child.");
    return a;
  }
};
exports.Component = E;
exports.Fragment = p;
exports.Profiler = r;
exports.PureComponent = G;
exports.StrictMode = q;
exports.Suspense = w;
exports.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = W;
exports.cloneElement = function (a, b, e) {
  if (null === a || void 0 === a) throw Error("React.cloneElement(...): The argument must be a React element, but you passed " + a + ".");
  var d = C({}, a.props),
    c = a.key,
    k = a.ref,
    h = a._owner;
  if (null != b) {
    void 0 !== b.ref && (k = b.ref, h = K.current);
    void 0 !== b.key && (c = "" + b.key);
    if (a.type && a.type.defaultProps) var g = a.type.defaultProps;
    for (f in b) J.call(b, f) && !L.hasOwnProperty(f) && (d[f] = void 0 === b[f] && void 0 !== g ? g[f] : b[f]);
  }
  var f = arguments.length - 2;
  if (1 === f) d.children = e;else if (1 < f) {
    g = Array(f);
    for (var m = 0; m < f; m++) g[m] = arguments[m + 2];
    d.children = g;
  }
  return {
    $$typeof: l,
    type: a.type,
    key: c,
    ref: k,
    props: d,
    _owner: h
  };
};
exports.createContext = function (a) {
  a = {
    $$typeof: u,
    _currentValue: a,
    _currentValue2: a,
    _threadCount: 0,
    Provider: null,
    Consumer: null,
    _defaultValue: null,
    _globalName: null
  };
  a.Provider = {
    $$typeof: t,
    _context: a
  };
  return a.Consumer = a;
};
exports.createElement = M;
exports.createFactory = function (a) {
  var b = M.bind(null, a);
  b.type = a;
  return b;
};
exports.createRef = function () {
  return {
    current: null
  };
};
exports.forwardRef = function (a) {
  return {
    $$typeof: v,
    render: a
  };
};
exports.isValidElement = O;
exports.lazy = function (a) {
  return {
    $$typeof: y,
    _payload: {
      _status: -1,
      _result: a
    },
    _init: T
  };
};
exports.memo = function (a, b) {
  return {
    $$typeof: x,
    type: a,
    compare: void 0 === b ? null : b
  };
};
exports.startTransition = function (a) {
  var b = V.transition;
  V.transition = {};
  try {
    a();
  } finally {
    V.transition = b;
  }
};
exports.unstable_act = function () {
  throw Error("act(...) is not supported in production builds of React.");
};
exports.useCallback = function (a, b) {
  return U.current.useCallback(a, b);
};
exports.useContext = function (a) {
  return U.current.useContext(a);
};
exports.useDebugValue = function () {};
exports.useDeferredValue = function (a) {
  return U.current.useDeferredValue(a);
};
exports.useEffect = function (a, b) {
  return U.current.useEffect(a, b);
};
exports.useId = function () {
  return U.current.useId();
};
exports.useImperativeHandle = function (a, b, e) {
  return U.current.useImperativeHandle(a, b, e);
};
exports.useInsertionEffect = function (a, b) {
  return U.current.useInsertionEffect(a, b);
};
exports.useLayoutEffect = function (a, b) {
  return U.current.useLayoutEffect(a, b);
};
exports.useMemo = function (a, b) {
  return U.current.useMemo(a, b);
};
exports.useReducer = function (a, b, e) {
  return U.current.useReducer(a, b, e);
};
exports.useRef = function (a) {
  return U.current.useRef(a);
};
exports.useState = function (a) {
  return U.current.useState(a);
};
exports.useSyncExternalStore = function (a, b, e) {
  return U.current.useSyncExternalStore(a, b, e);
};
exports.useTransition = function () {
  return U.current.useTransition();
};
exports.version = "18.2.0";
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJsIiwiU3ltYm9sIiwiZm9yIiwibiIsInAiLCJxIiwiciIsInQiLCJ1IiwidiIsInciLCJ4IiwieSIsInoiLCJpdGVyYXRvciIsIkEiLCJhIiwiQiIsImlzTW91bnRlZCIsImVucXVldWVGb3JjZVVwZGF0ZSIsImVucXVldWVSZXBsYWNlU3RhdGUiLCJlbnF1ZXVlU2V0U3RhdGUiLCJDIiwiT2JqZWN0IiwiYXNzaWduIiwiRCIsIkUiLCJiIiwiZSIsInByb3BzIiwiY29udGV4dCIsInJlZnMiLCJ1cGRhdGVyIiwicHJvdG90eXBlIiwiaXNSZWFjdENvbXBvbmVudCIsInNldFN0YXRlIiwiRXJyb3IiLCJmb3JjZVVwZGF0ZSIsIkYiLCJHIiwiSCIsImNvbnN0cnVjdG9yIiwiaXNQdXJlUmVhY3RDb21wb25lbnQiLCJJIiwiQXJyYXkiLCJpc0FycmF5IiwiSiIsImhhc093blByb3BlcnR5IiwiSyIsImN1cnJlbnQiLCJMIiwia2V5IiwicmVmIiwiX19zZWxmIiwiX19zb3VyY2UiLCJNIiwiZCIsImMiLCJrIiwiaCIsImNhbGwiLCJnIiwiYXJndW1lbnRzIiwibGVuZ3RoIiwiY2hpbGRyZW4iLCJmIiwibSIsImRlZmF1bHRQcm9wcyIsIiQkdHlwZW9mIiwidHlwZSIsIl9vd25lciIsIk4iLCJPIiwiZXNjYXBlIiwicmVwbGFjZSIsIlAiLCJRIiwidG9TdHJpbmciLCJSIiwicHVzaCIsIm5leHQiLCJkb25lIiwidmFsdWUiLCJTdHJpbmciLCJrZXlzIiwiam9pbiIsIlMiLCJUIiwiX3N0YXR1cyIsIl9yZXN1bHQiLCJ0aGVuIiwiZGVmYXVsdCIsIlUiLCJWIiwidHJhbnNpdGlvbiIsIlciLCJSZWFjdEN1cnJlbnREaXNwYXRjaGVyIiwiUmVhY3RDdXJyZW50QmF0Y2hDb25maWciLCJSZWFjdEN1cnJlbnRPd25lciIsImV4cG9ydHMiLCJDaGlsZHJlbiIsIm1hcCIsImZvckVhY2giLCJhcHBseSIsImNvdW50IiwidG9BcnJheSIsIm9ubHkiLCJDb21wb25lbnQiLCJGcmFnbWVudCIsIlByb2ZpbGVyIiwiUHVyZUNvbXBvbmVudCIsIlN0cmljdE1vZGUiLCJTdXNwZW5zZSIsIl9fU0VDUkVUX0lOVEVSTkFMU19ET19OT1RfVVNFX09SX1lPVV9XSUxMX0JFX0ZJUkVEIiwiY2xvbmVFbGVtZW50IiwiY3JlYXRlQ29udGV4dCIsIl9jdXJyZW50VmFsdWUiLCJfY3VycmVudFZhbHVlMiIsIl90aHJlYWRDb3VudCIsIlByb3ZpZGVyIiwiQ29uc3VtZXIiLCJfZGVmYXVsdFZhbHVlIiwiX2dsb2JhbE5hbWUiLCJfY29udGV4dCIsImNyZWF0ZUVsZW1lbnQiLCJjcmVhdGVGYWN0b3J5IiwiYmluZCIsImNyZWF0ZVJlZiIsImZvcndhcmRSZWYiLCJyZW5kZXIiLCJpc1ZhbGlkRWxlbWVudCIsImxhenkiLCJfcGF5bG9hZCIsIl9pbml0IiwibWVtbyIsImNvbXBhcmUiLCJzdGFydFRyYW5zaXRpb24iLCJ1bnN0YWJsZV9hY3QiLCJ1c2VDYWxsYmFjayIsInVzZUNvbnRleHQiLCJ1c2VEZWJ1Z1ZhbHVlIiwidXNlRGVmZXJyZWRWYWx1ZSIsInVzZUVmZmVjdCIsInVzZUlkIiwidXNlSW1wZXJhdGl2ZUhhbmRsZSIsInVzZUluc2VydGlvbkVmZmVjdCIsInVzZUxheW91dEVmZmVjdCIsInVzZU1lbW8iLCJ1c2VSZWR1Y2VyIiwidXNlUmVmIiwidXNlU3RhdGUiLCJ1c2VTeW5jRXh0ZXJuYWxTdG9yZSIsInVzZVRyYW5zaXRpb24iLCJ2ZXJzaW9uIl0sInNvdXJjZXMiOlsicmVhY3QucHJvZHVjdGlvbi5taW4uanMiXSwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBAbGljZW5zZSBSZWFjdFxuICogcmVhY3QucHJvZHVjdGlvbi5taW4uanNcbiAqXG4gKiBDb3B5cmlnaHQgKGMpIEZhY2Vib29rLCBJbmMuIGFuZCBpdHMgYWZmaWxpYXRlcy5cbiAqXG4gKiBUaGlzIHNvdXJjZSBjb2RlIGlzIGxpY2Vuc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZSBmb3VuZCBpbiB0aGVcbiAqIExJQ0VOU0UgZmlsZSBpbiB0aGUgcm9vdCBkaXJlY3Rvcnkgb2YgdGhpcyBzb3VyY2UgdHJlZS5cbiAqL1xuJ3VzZSBzdHJpY3QnO3ZhciBsPVN5bWJvbC5mb3IoXCJyZWFjdC5lbGVtZW50XCIpLG49U3ltYm9sLmZvcihcInJlYWN0LnBvcnRhbFwiKSxwPVN5bWJvbC5mb3IoXCJyZWFjdC5mcmFnbWVudFwiKSxxPVN5bWJvbC5mb3IoXCJyZWFjdC5zdHJpY3RfbW9kZVwiKSxyPVN5bWJvbC5mb3IoXCJyZWFjdC5wcm9maWxlclwiKSx0PVN5bWJvbC5mb3IoXCJyZWFjdC5wcm92aWRlclwiKSx1PVN5bWJvbC5mb3IoXCJyZWFjdC5jb250ZXh0XCIpLHY9U3ltYm9sLmZvcihcInJlYWN0LmZvcndhcmRfcmVmXCIpLHc9U3ltYm9sLmZvcihcInJlYWN0LnN1c3BlbnNlXCIpLHg9U3ltYm9sLmZvcihcInJlYWN0Lm1lbW9cIikseT1TeW1ib2wuZm9yKFwicmVhY3QubGF6eVwiKSx6PVN5bWJvbC5pdGVyYXRvcjtmdW5jdGlvbiBBKGEpe2lmKG51bGw9PT1hfHxcIm9iamVjdFwiIT09dHlwZW9mIGEpcmV0dXJuIG51bGw7YT16JiZhW3pdfHxhW1wiQEBpdGVyYXRvclwiXTtyZXR1cm5cImZ1bmN0aW9uXCI9PT10eXBlb2YgYT9hOm51bGx9XG52YXIgQj17aXNNb3VudGVkOmZ1bmN0aW9uKCl7cmV0dXJuITF9LGVucXVldWVGb3JjZVVwZGF0ZTpmdW5jdGlvbigpe30sZW5xdWV1ZVJlcGxhY2VTdGF0ZTpmdW5jdGlvbigpe30sZW5xdWV1ZVNldFN0YXRlOmZ1bmN0aW9uKCl7fX0sQz1PYmplY3QuYXNzaWduLEQ9e307ZnVuY3Rpb24gRShhLGIsZSl7dGhpcy5wcm9wcz1hO3RoaXMuY29udGV4dD1iO3RoaXMucmVmcz1EO3RoaXMudXBkYXRlcj1lfHxCfUUucHJvdG90eXBlLmlzUmVhY3RDb21wb25lbnQ9e307XG5FLnByb3RvdHlwZS5zZXRTdGF0ZT1mdW5jdGlvbihhLGIpe2lmKFwib2JqZWN0XCIhPT10eXBlb2YgYSYmXCJmdW5jdGlvblwiIT09dHlwZW9mIGEmJm51bGwhPWEpdGhyb3cgRXJyb3IoXCJzZXRTdGF0ZSguLi4pOiB0YWtlcyBhbiBvYmplY3Qgb2Ygc3RhdGUgdmFyaWFibGVzIHRvIHVwZGF0ZSBvciBhIGZ1bmN0aW9uIHdoaWNoIHJldHVybnMgYW4gb2JqZWN0IG9mIHN0YXRlIHZhcmlhYmxlcy5cIik7dGhpcy51cGRhdGVyLmVucXVldWVTZXRTdGF0ZSh0aGlzLGEsYixcInNldFN0YXRlXCIpfTtFLnByb3RvdHlwZS5mb3JjZVVwZGF0ZT1mdW5jdGlvbihhKXt0aGlzLnVwZGF0ZXIuZW5xdWV1ZUZvcmNlVXBkYXRlKHRoaXMsYSxcImZvcmNlVXBkYXRlXCIpfTtmdW5jdGlvbiBGKCl7fUYucHJvdG90eXBlPUUucHJvdG90eXBlO2Z1bmN0aW9uIEcoYSxiLGUpe3RoaXMucHJvcHM9YTt0aGlzLmNvbnRleHQ9Yjt0aGlzLnJlZnM9RDt0aGlzLnVwZGF0ZXI9ZXx8Qn12YXIgSD1HLnByb3RvdHlwZT1uZXcgRjtcbkguY29uc3RydWN0b3I9RztDKEgsRS5wcm90b3R5cGUpO0guaXNQdXJlUmVhY3RDb21wb25lbnQ9ITA7dmFyIEk9QXJyYXkuaXNBcnJheSxKPU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHksSz17Y3VycmVudDpudWxsfSxMPXtrZXk6ITAscmVmOiEwLF9fc2VsZjohMCxfX3NvdXJjZTohMH07XG5mdW5jdGlvbiBNKGEsYixlKXt2YXIgZCxjPXt9LGs9bnVsbCxoPW51bGw7aWYobnVsbCE9Yilmb3IoZCBpbiB2b2lkIDAhPT1iLnJlZiYmKGg9Yi5yZWYpLHZvaWQgMCE9PWIua2V5JiYoaz1cIlwiK2Iua2V5KSxiKUouY2FsbChiLGQpJiYhTC5oYXNPd25Qcm9wZXJ0eShkKSYmKGNbZF09YltkXSk7dmFyIGc9YXJndW1lbnRzLmxlbmd0aC0yO2lmKDE9PT1nKWMuY2hpbGRyZW49ZTtlbHNlIGlmKDE8Zyl7Zm9yKHZhciBmPUFycmF5KGcpLG09MDttPGc7bSsrKWZbbV09YXJndW1lbnRzW20rMl07Yy5jaGlsZHJlbj1mfWlmKGEmJmEuZGVmYXVsdFByb3BzKWZvcihkIGluIGc9YS5kZWZhdWx0UHJvcHMsZyl2b2lkIDA9PT1jW2RdJiYoY1tkXT1nW2RdKTtyZXR1cm57JCR0eXBlb2Y6bCx0eXBlOmEsa2V5OmsscmVmOmgscHJvcHM6Yyxfb3duZXI6Sy5jdXJyZW50fX1cbmZ1bmN0aW9uIE4oYSxiKXtyZXR1cm57JCR0eXBlb2Y6bCx0eXBlOmEudHlwZSxrZXk6YixyZWY6YS5yZWYscHJvcHM6YS5wcm9wcyxfb3duZXI6YS5fb3duZXJ9fWZ1bmN0aW9uIE8oYSl7cmV0dXJuXCJvYmplY3RcIj09PXR5cGVvZiBhJiZudWxsIT09YSYmYS4kJHR5cGVvZj09PWx9ZnVuY3Rpb24gZXNjYXBlKGEpe3ZhciBiPXtcIj1cIjpcIj0wXCIsXCI6XCI6XCI9MlwifTtyZXR1cm5cIiRcIithLnJlcGxhY2UoL1s9Ol0vZyxmdW5jdGlvbihhKXtyZXR1cm4gYlthXX0pfXZhciBQPS9cXC8rL2c7ZnVuY3Rpb24gUShhLGIpe3JldHVyblwib2JqZWN0XCI9PT10eXBlb2YgYSYmbnVsbCE9PWEmJm51bGwhPWEua2V5P2VzY2FwZShcIlwiK2Eua2V5KTpiLnRvU3RyaW5nKDM2KX1cbmZ1bmN0aW9uIFIoYSxiLGUsZCxjKXt2YXIgaz10eXBlb2YgYTtpZihcInVuZGVmaW5lZFwiPT09a3x8XCJib29sZWFuXCI9PT1rKWE9bnVsbDt2YXIgaD0hMTtpZihudWxsPT09YSloPSEwO2Vsc2Ugc3dpdGNoKGspe2Nhc2UgXCJzdHJpbmdcIjpjYXNlIFwibnVtYmVyXCI6aD0hMDticmVhaztjYXNlIFwib2JqZWN0XCI6c3dpdGNoKGEuJCR0eXBlb2Ype2Nhc2UgbDpjYXNlIG46aD0hMH19aWYoaClyZXR1cm4gaD1hLGM9YyhoKSxhPVwiXCI9PT1kP1wiLlwiK1EoaCwwKTpkLEkoYyk/KGU9XCJcIixudWxsIT1hJiYoZT1hLnJlcGxhY2UoUCxcIiQmL1wiKStcIi9cIiksUihjLGIsZSxcIlwiLGZ1bmN0aW9uKGEpe3JldHVybiBhfSkpOm51bGwhPWMmJihPKGMpJiYoYz1OKGMsZSsoIWMua2V5fHxoJiZoLmtleT09PWMua2V5P1wiXCI6KFwiXCIrYy5rZXkpLnJlcGxhY2UoUCxcIiQmL1wiKStcIi9cIikrYSkpLGIucHVzaChjKSksMTtoPTA7ZD1cIlwiPT09ZD9cIi5cIjpkK1wiOlwiO2lmKEkoYSkpZm9yKHZhciBnPTA7ZzxhLmxlbmd0aDtnKyspe2s9XG5hW2ddO3ZhciBmPWQrUShrLGcpO2grPVIoayxiLGUsZixjKX1lbHNlIGlmKGY9QShhKSxcImZ1bmN0aW9uXCI9PT10eXBlb2YgZilmb3IoYT1mLmNhbGwoYSksZz0wOyEoaz1hLm5leHQoKSkuZG9uZTspaz1rLnZhbHVlLGY9ZCtRKGssZysrKSxoKz1SKGssYixlLGYsYyk7ZWxzZSBpZihcIm9iamVjdFwiPT09ayl0aHJvdyBiPVN0cmluZyhhKSxFcnJvcihcIk9iamVjdHMgYXJlIG5vdCB2YWxpZCBhcyBhIFJlYWN0IGNoaWxkIChmb3VuZDogXCIrKFwiW29iamVjdCBPYmplY3RdXCI9PT1iP1wib2JqZWN0IHdpdGgga2V5cyB7XCIrT2JqZWN0LmtleXMoYSkuam9pbihcIiwgXCIpK1wifVwiOmIpK1wiKS4gSWYgeW91IG1lYW50IHRvIHJlbmRlciBhIGNvbGxlY3Rpb24gb2YgY2hpbGRyZW4sIHVzZSBhbiBhcnJheSBpbnN0ZWFkLlwiKTtyZXR1cm4gaH1cbmZ1bmN0aW9uIFMoYSxiLGUpe2lmKG51bGw9PWEpcmV0dXJuIGE7dmFyIGQ9W10sYz0wO1IoYSxkLFwiXCIsXCJcIixmdW5jdGlvbihhKXtyZXR1cm4gYi5jYWxsKGUsYSxjKyspfSk7cmV0dXJuIGR9ZnVuY3Rpb24gVChhKXtpZigtMT09PWEuX3N0YXR1cyl7dmFyIGI9YS5fcmVzdWx0O2I9YigpO2IudGhlbihmdW5jdGlvbihiKXtpZigwPT09YS5fc3RhdHVzfHwtMT09PWEuX3N0YXR1cylhLl9zdGF0dXM9MSxhLl9yZXN1bHQ9Yn0sZnVuY3Rpb24oYil7aWYoMD09PWEuX3N0YXR1c3x8LTE9PT1hLl9zdGF0dXMpYS5fc3RhdHVzPTIsYS5fcmVzdWx0PWJ9KTstMT09PWEuX3N0YXR1cyYmKGEuX3N0YXR1cz0wLGEuX3Jlc3VsdD1iKX1pZigxPT09YS5fc3RhdHVzKXJldHVybiBhLl9yZXN1bHQuZGVmYXVsdDt0aHJvdyBhLl9yZXN1bHQ7fVxudmFyIFU9e2N1cnJlbnQ6bnVsbH0sVj17dHJhbnNpdGlvbjpudWxsfSxXPXtSZWFjdEN1cnJlbnREaXNwYXRjaGVyOlUsUmVhY3RDdXJyZW50QmF0Y2hDb25maWc6VixSZWFjdEN1cnJlbnRPd25lcjpLfTtleHBvcnRzLkNoaWxkcmVuPXttYXA6Uyxmb3JFYWNoOmZ1bmN0aW9uKGEsYixlKXtTKGEsZnVuY3Rpb24oKXtiLmFwcGx5KHRoaXMsYXJndW1lbnRzKX0sZSl9LGNvdW50OmZ1bmN0aW9uKGEpe3ZhciBiPTA7UyhhLGZ1bmN0aW9uKCl7YisrfSk7cmV0dXJuIGJ9LHRvQXJyYXk6ZnVuY3Rpb24oYSl7cmV0dXJuIFMoYSxmdW5jdGlvbihhKXtyZXR1cm4gYX0pfHxbXX0sb25seTpmdW5jdGlvbihhKXtpZighTyhhKSl0aHJvdyBFcnJvcihcIlJlYWN0LkNoaWxkcmVuLm9ubHkgZXhwZWN0ZWQgdG8gcmVjZWl2ZSBhIHNpbmdsZSBSZWFjdCBlbGVtZW50IGNoaWxkLlwiKTtyZXR1cm4gYX19O2V4cG9ydHMuQ29tcG9uZW50PUU7ZXhwb3J0cy5GcmFnbWVudD1wO1xuZXhwb3J0cy5Qcm9maWxlcj1yO2V4cG9ydHMuUHVyZUNvbXBvbmVudD1HO2V4cG9ydHMuU3RyaWN0TW9kZT1xO2V4cG9ydHMuU3VzcGVuc2U9dztleHBvcnRzLl9fU0VDUkVUX0lOVEVSTkFMU19ET19OT1RfVVNFX09SX1lPVV9XSUxMX0JFX0ZJUkVEPVc7XG5leHBvcnRzLmNsb25lRWxlbWVudD1mdW5jdGlvbihhLGIsZSl7aWYobnVsbD09PWF8fHZvaWQgMD09PWEpdGhyb3cgRXJyb3IoXCJSZWFjdC5jbG9uZUVsZW1lbnQoLi4uKTogVGhlIGFyZ3VtZW50IG11c3QgYmUgYSBSZWFjdCBlbGVtZW50LCBidXQgeW91IHBhc3NlZCBcIithK1wiLlwiKTt2YXIgZD1DKHt9LGEucHJvcHMpLGM9YS5rZXksaz1hLnJlZixoPWEuX293bmVyO2lmKG51bGwhPWIpe3ZvaWQgMCE9PWIucmVmJiYoaz1iLnJlZixoPUsuY3VycmVudCk7dm9pZCAwIT09Yi5rZXkmJihjPVwiXCIrYi5rZXkpO2lmKGEudHlwZSYmYS50eXBlLmRlZmF1bHRQcm9wcyl2YXIgZz1hLnR5cGUuZGVmYXVsdFByb3BzO2ZvcihmIGluIGIpSi5jYWxsKGIsZikmJiFMLmhhc093blByb3BlcnR5KGYpJiYoZFtmXT12b2lkIDA9PT1iW2ZdJiZ2b2lkIDAhPT1nP2dbZl06YltmXSl9dmFyIGY9YXJndW1lbnRzLmxlbmd0aC0yO2lmKDE9PT1mKWQuY2hpbGRyZW49ZTtlbHNlIGlmKDE8Zil7Zz1BcnJheShmKTtcbmZvcih2YXIgbT0wO208ZjttKyspZ1ttXT1hcmd1bWVudHNbbSsyXTtkLmNoaWxkcmVuPWd9cmV0dXJueyQkdHlwZW9mOmwsdHlwZTphLnR5cGUsa2V5OmMscmVmOmsscHJvcHM6ZCxfb3duZXI6aH19O2V4cG9ydHMuY3JlYXRlQ29udGV4dD1mdW5jdGlvbihhKXthPXskJHR5cGVvZjp1LF9jdXJyZW50VmFsdWU6YSxfY3VycmVudFZhbHVlMjphLF90aHJlYWRDb3VudDowLFByb3ZpZGVyOm51bGwsQ29uc3VtZXI6bnVsbCxfZGVmYXVsdFZhbHVlOm51bGwsX2dsb2JhbE5hbWU6bnVsbH07YS5Qcm92aWRlcj17JCR0eXBlb2Y6dCxfY29udGV4dDphfTtyZXR1cm4gYS5Db25zdW1lcj1hfTtleHBvcnRzLmNyZWF0ZUVsZW1lbnQ9TTtleHBvcnRzLmNyZWF0ZUZhY3Rvcnk9ZnVuY3Rpb24oYSl7dmFyIGI9TS5iaW5kKG51bGwsYSk7Yi50eXBlPWE7cmV0dXJuIGJ9O2V4cG9ydHMuY3JlYXRlUmVmPWZ1bmN0aW9uKCl7cmV0dXJue2N1cnJlbnQ6bnVsbH19O1xuZXhwb3J0cy5mb3J3YXJkUmVmPWZ1bmN0aW9uKGEpe3JldHVybnskJHR5cGVvZjp2LHJlbmRlcjphfX07ZXhwb3J0cy5pc1ZhbGlkRWxlbWVudD1PO2V4cG9ydHMubGF6eT1mdW5jdGlvbihhKXtyZXR1cm57JCR0eXBlb2Y6eSxfcGF5bG9hZDp7X3N0YXR1czotMSxfcmVzdWx0OmF9LF9pbml0OlR9fTtleHBvcnRzLm1lbW89ZnVuY3Rpb24oYSxiKXtyZXR1cm57JCR0eXBlb2Y6eCx0eXBlOmEsY29tcGFyZTp2b2lkIDA9PT1iP251bGw6Yn19O2V4cG9ydHMuc3RhcnRUcmFuc2l0aW9uPWZ1bmN0aW9uKGEpe3ZhciBiPVYudHJhbnNpdGlvbjtWLnRyYW5zaXRpb249e307dHJ5e2EoKX1maW5hbGx5e1YudHJhbnNpdGlvbj1ifX07ZXhwb3J0cy51bnN0YWJsZV9hY3Q9ZnVuY3Rpb24oKXt0aHJvdyBFcnJvcihcImFjdCguLi4pIGlzIG5vdCBzdXBwb3J0ZWQgaW4gcHJvZHVjdGlvbiBidWlsZHMgb2YgUmVhY3QuXCIpO307XG5leHBvcnRzLnVzZUNhbGxiYWNrPWZ1bmN0aW9uKGEsYil7cmV0dXJuIFUuY3VycmVudC51c2VDYWxsYmFjayhhLGIpfTtleHBvcnRzLnVzZUNvbnRleHQ9ZnVuY3Rpb24oYSl7cmV0dXJuIFUuY3VycmVudC51c2VDb250ZXh0KGEpfTtleHBvcnRzLnVzZURlYnVnVmFsdWU9ZnVuY3Rpb24oKXt9O2V4cG9ydHMudXNlRGVmZXJyZWRWYWx1ZT1mdW5jdGlvbihhKXtyZXR1cm4gVS5jdXJyZW50LnVzZURlZmVycmVkVmFsdWUoYSl9O2V4cG9ydHMudXNlRWZmZWN0PWZ1bmN0aW9uKGEsYil7cmV0dXJuIFUuY3VycmVudC51c2VFZmZlY3QoYSxiKX07ZXhwb3J0cy51c2VJZD1mdW5jdGlvbigpe3JldHVybiBVLmN1cnJlbnQudXNlSWQoKX07ZXhwb3J0cy51c2VJbXBlcmF0aXZlSGFuZGxlPWZ1bmN0aW9uKGEsYixlKXtyZXR1cm4gVS5jdXJyZW50LnVzZUltcGVyYXRpdmVIYW5kbGUoYSxiLGUpfTtcbmV4cG9ydHMudXNlSW5zZXJ0aW9uRWZmZWN0PWZ1bmN0aW9uKGEsYil7cmV0dXJuIFUuY3VycmVudC51c2VJbnNlcnRpb25FZmZlY3QoYSxiKX07ZXhwb3J0cy51c2VMYXlvdXRFZmZlY3Q9ZnVuY3Rpb24oYSxiKXtyZXR1cm4gVS5jdXJyZW50LnVzZUxheW91dEVmZmVjdChhLGIpfTtleHBvcnRzLnVzZU1lbW89ZnVuY3Rpb24oYSxiKXtyZXR1cm4gVS5jdXJyZW50LnVzZU1lbW8oYSxiKX07ZXhwb3J0cy51c2VSZWR1Y2VyPWZ1bmN0aW9uKGEsYixlKXtyZXR1cm4gVS5jdXJyZW50LnVzZVJlZHVjZXIoYSxiLGUpfTtleHBvcnRzLnVzZVJlZj1mdW5jdGlvbihhKXtyZXR1cm4gVS5jdXJyZW50LnVzZVJlZihhKX07ZXhwb3J0cy51c2VTdGF0ZT1mdW5jdGlvbihhKXtyZXR1cm4gVS5jdXJyZW50LnVzZVN0YXRlKGEpfTtleHBvcnRzLnVzZVN5bmNFeHRlcm5hbFN0b3JlPWZ1bmN0aW9uKGEsYixlKXtyZXR1cm4gVS5jdXJyZW50LnVzZVN5bmNFeHRlcm5hbFN0b3JlKGEsYixlKX07XG5leHBvcnRzLnVzZVRyYW5zaXRpb249ZnVuY3Rpb24oKXtyZXR1cm4gVS5jdXJyZW50LnVzZVRyYW5zaXRpb24oKX07ZXhwb3J0cy52ZXJzaW9uPVwiMTguMi4wXCI7XG4iXSwibWFwcGluZ3MiOiJBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVk7O0FBQUMsSUFBSUEsQ0FBQyxHQUFDQyxNQUFNLENBQUNDLEdBQUcsQ0FBQyxlQUFlLENBQUM7RUFBQ0MsQ0FBQyxHQUFDRixNQUFNLENBQUNDLEdBQUcsQ0FBQyxjQUFjLENBQUM7RUFBQ0UsQ0FBQyxHQUFDSCxNQUFNLENBQUNDLEdBQUcsQ0FBQyxnQkFBZ0IsQ0FBQztFQUFDRyxDQUFDLEdBQUNKLE1BQU0sQ0FBQ0MsR0FBRyxDQUFDLG1CQUFtQixDQUFDO0VBQUNJLENBQUMsR0FBQ0wsTUFBTSxDQUFDQyxHQUFHLENBQUMsZ0JBQWdCLENBQUM7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
},{}],14:[function(require,module,exports){
(function (process){
'use strict';

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./cjs/react.production.min.js');
} else {
  module.exports = require('./cjs/react.development.js');
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwcm9jZXNzIiwiZW52IiwiTk9ERV9FTlYiLCJtb2R1bGUiLCJleHBvcnRzIiwicmVxdWlyZSJdLCJzb3VyY2VzIjpbImluZGV4LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcblxuaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicpIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2Nqcy9yZWFjdC5wcm9kdWN0aW9uLm1pbi5qcycpO1xufSBlbHNlIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2Nqcy9yZWFjdC5kZXZlbG9wbWVudC5qcycpO1xufVxuIl0sIm1hcHBpbmdzIjoiQUFBQSxZQUFZOztBQUVaLElBQUlBLE9BQU8sQ0FBQ0MsR0FBRyxDQUFDQyxRQUFRLEtBQUssWUFBWSxFQUFFO0VBQ3pDQyxNQUFNLENBQUNDLE9BQU8sR0FBR0MsT0FBTyxDQUFDLCtCQUErQixDQUFDO0FBQzNELENBQUMsTUFBTTtFQUNMRixNQUFNLENBQUNDLE9BQU8sR0FBR0MsT0FBTyxDQUFDLDRCQUE0QixDQUFDO0FBQ3hEIn0=
}).call(this,require("Xp6JUx"))
},{"./cjs/react.development.js":12,"./cjs/react.production.min.js":13,"Xp6JUx":2}],15:[function(require,module,exports){
"use strict";

var _react = _interopRequireWildcard(require("react"));
var _propTypes = _interopRequireDefault(require("prop-types"));
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function _getRequireWildcardCache(nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }
function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || _typeof(obj) !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }
function _typeof(obj) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (obj) { return typeof obj; } : function (obj) { return obj && "function" == typeof Symbol && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }, _typeof(obj); }
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor); } }
function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); Object.defineProperty(Constructor, "prototype", { writable: false }); return Constructor; }
function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); Object.defineProperty(subClass, "prototype", { writable: false }); if (superClass) _setPrototypeOf(subClass, superClass); }
function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }
function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = _getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = _getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return _possibleConstructorReturn(this, result); }; }
function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } else if (call !== void 0) { throw new TypeError("Derived constructors may only return object or undefined"); } return _assertThisInitialized(self); }
function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }
function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {})); return true; } catch (e) { return false; } }
function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }
function _defineProperty(obj, key, value) { key = _toPropertyKey(key); if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }
function _toPropertyKey(arg) { var key = _toPrimitive(arg, "string"); return _typeof(key) === "symbol" ? key : String(key); }
function _toPrimitive(input, hint) { if (_typeof(input) !== "object" || input === null) return input; var prim = input[Symbol.toPrimitive]; if (prim !== undefined) { var res = prim.call(input, hint || "default"); if (_typeof(res) !== "object") return res; throw new TypeError("@@toPrimitive must return a primitive value."); } return (hint === "string" ? String : Number)(input); }
/**
 * WPFormsSelector component.
 *
 * @since 1.6.3
 */
var WPFormsSelector = /*#__PURE__*/function (_Component) {
  _inherits(WPFormsSelector, _Component);
  var _super = _createSuper(WPFormsSelector);
  /**
   * Module slug.
   *
   * @since 1.6.3
   *
   * @type {string}
   */

  /**
   * Constructor.
   *
   * @since 1.6.3
   *
   * @param {string} props List of properties.
   */
  function WPFormsSelector(props) {
    var _this;
    _classCallCheck(this, WPFormsSelector);
    _this = _super.call(this, props);
    _this.state = {
      error: null,
      isLoading: true,
      form: null
    };
    return _this;
  }

  /**
   * Set types for properties.
   *
   * @since 1.6.3
   *
   * @returns {object} Properties type.
   */
  _createClass(WPFormsSelector, [{
    key: "componentDidUpdate",
    value:
    /**
     * Check if form settings was updated.
     *
     * @since 1.6.3
     *
     * @param {object} prevProps List of previous properties.
     */
    function componentDidUpdate(prevProps) {
      if (prevProps.form_id !== this.props.form_id || prevProps.show_title !== this.props.show_title || prevProps.show_desc !== this.props.show_desc) {
        this.componentDidMount();
      }
    }

    /**
     * Ajax request for form HTML.
     *
     * @since 1.6.3
     */
  }, {
    key: "componentDidMount",
    value: function componentDidMount() {
      var _this2 = this;
      var formData = new FormData();
      formData.append('nonce', wpforms_divi_builder.nonce);
      formData.append('action', 'wpforms_divi_preview');
      formData.append('form_id', this.props.form_id);
      formData.append('show_title', this.props.show_title);
      formData.append('show_desc', this.props.show_desc);
      fetch(wpforms_divi_builder.ajax_url, {
        method: 'POST',
        cache: 'no-cache',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Cache-Control': 'no-cache'
        },
        body: new URLSearchParams(formData)
      }).then(function (res) {
        return res.json();
      }).then(function (result) {
        _this2.setState({
          isLoading: false,
          form: result.data
        });
      }, function (error) {
        _this2.setState({
          isLoading: false,
          error: error
        });
      });
    }

    /**
     * Render module view.
     *
     * @since 1.6.3
     *
     * @returns {JSX.Element} View for module.
     */
  }, {
    key: "render",
    value: function render() {
      var _this$state = this.state,
        error = _this$state.error,
        isLoaded = _this$state.isLoaded,
        form = _this$state.form,
        wrapperClasses = isLoaded ? 'wpforms-divi-form-preview loading' : 'wpforms-divi-form-preview';
      if (error || !form) {
        return /*#__PURE__*/_react.default.createElement("div", {
          className: "wpforms-divi-form-placeholder"
        }, /*#__PURE__*/_react.default.createElement("img", {
          src: wpforms_divi_builder.placeholder
        }), /*#__PURE__*/_react.default.createElement("h3", null, wpforms_divi_builder.placeholder_title));
      }
      return /*#__PURE__*/_react.default.createElement("div", {
        className: wrapperClasses
      }, /*#__PURE__*/_react.default.createElement("div", {
        dangerouslySetInnerHTML: {
          __html: form
        }
      }));
    }
  }], [{
    key: "propTypes",
    get: function get() {
      return {
        form_id: _propTypes.default.number,
        // eslint-disable-line camelcase
        show_title: _propTypes.default.string,
        // eslint-disable-line camelcase
        show_desc: _propTypes.default.string // eslint-disable-line camelcase
      };
    }
  }]);
  return WPFormsSelector;
}(_react.Component);
_defineProperty(WPFormsSelector, "slug", 'wpforms_selector');
jQuery(window)

// Register custom modules.
.on('et_builder_api_ready', function (event, API) {
  API.registerModules([WPFormsSelector]);
})

// Re-initialize WPForms frontend.
.on('wpformsDiviModuleDisplay', function (event) {
  window.wpforms.init();
});

// Make all the modern dropdowns disabled.
jQuery(document).on('wpformsReady', function (event) {
  var $ = jQuery;
  $('.choicesjs-select').each(function () {
    var $instance = $(this).data('choicesjs');
    if (!$instance || typeof $instance.disable !== 'function') {
      return;
    }
    $instance.disable();
  });
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJXUEZvcm1zU2VsZWN0b3IiLCJwcm9wcyIsInN0YXRlIiwiZXJyb3IiLCJpc0xvYWRpbmciLCJmb3JtIiwicHJldlByb3BzIiwiZm9ybV9pZCIsInNob3dfdGl0bGUiLCJzaG93X2Rlc2MiLCJjb21wb25lbnREaWRNb3VudCIsImZvcm1EYXRhIiwiRm9ybURhdGEiLCJhcHBlbmQiLCJ3cGZvcm1zX2RpdmlfYnVpbGRlciIsIm5vbmNlIiwiZmV0Y2giLCJhamF4X3VybCIsIm1ldGhvZCIsImNhY2hlIiwiY3JlZGVudGlhbHMiLCJoZWFkZXJzIiwiYm9keSIsIlVSTFNlYXJjaFBhcmFtcyIsInRoZW4iLCJyZXMiLCJqc29uIiwicmVzdWx0Iiwic2V0U3RhdGUiLCJkYXRhIiwiaXNMb2FkZWQiLCJ3cmFwcGVyQ2xhc3NlcyIsInBsYWNlaG9sZGVyIiwicGxhY2Vob2xkZXJfdGl0bGUiLCJfX2h0bWwiLCJQcm9wVHlwZXMiLCJudW1iZXIiLCJzdHJpbmciLCJDb21wb25lbnQiLCJqUXVlcnkiLCJ3aW5kb3ciLCJvbiIsImV2ZW50IiwiQVBJIiwicmVnaXN0ZXJNb2R1bGVzIiwid3Bmb3JtcyIsImluaXQiLCJkb2N1bWVudCIsIiQiLCJlYWNoIiwiJGluc3RhbmNlIiwiZGlzYWJsZSJdLCJzb3VyY2VzIjpbImZha2VfOTMwNWJlNDQuanMiXSwic291cmNlc0NvbnRlbnQiOlsiLyogZ2xvYmFsIHdwZm9ybXNfZGl2aV9idWlsZGVyICovXG5cbmltcG9ydCBSZWFjdCwgeyBDb21wb25lbnQgfSBmcm9tICdyZWFjdCc7XG5pbXBvcnQgUHJvcFR5cGVzIGZyb20gJ3Byb3AtdHlwZXMnO1xuXG5cbi8qKlxuICogV1BGb3Jtc1NlbGVjdG9yIGNvbXBvbmVudC5cbiAqXG4gKiBAc2luY2UgMS42LjNcbiAqL1xuY2xhc3MgV1BGb3Jtc1NlbGVjdG9yIGV4dGVuZHMgQ29tcG9uZW50IHtcblxuXHQvKipcblx0ICogTW9kdWxlIHNsdWcuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjYuM1xuXHQgKlxuXHQgKiBAdHlwZSB7c3RyaW5nfVxuXHQgKi9cblx0c3RhdGljIHNsdWcgPSAnd3Bmb3Jtc19zZWxlY3Rvcic7XG5cblx0LyoqXG5cdCAqIENvbnN0cnVjdG9yLlxuXHQgKlxuXHQgKiBAc2luY2UgMS42LjNcblx0ICpcblx0ICogQHBhcmFtIHtzdHJpbmd9IHByb3BzIExpc3Qgb2YgcHJvcGVydGllcy5cblx0ICovXG5cdGNvbnN0cnVjdG9yKCBwcm9wcyApIHtcblxuXHRcdHN1cGVyKCBwcm9wcyApO1xuXG5cdFx0dGhpcy5zdGF0ZSA9IHtcblx0XHRcdGVycm9yOiBudWxsLFxuXHRcdFx0aXNMb2FkaW5nOiB0cnVlLFxuXHRcdFx0Zm9ybTogbnVsbCxcblx0XHR9O1xuXHR9XG5cblx0LyoqXG5cdCAqIFNldCB0eXBlcyBmb3IgcHJvcGVydGllcy5cblx0ICpcblx0ICogQHNpbmNlIDEuNi4zXG5cdCAqXG5cdCAqIEByZXR1cm5zIHtvYmplY3R9IFByb3BlcnRpZXMgdHlwZS5cblx0ICovXG5cdHN0YXRpYyBnZXQgcHJvcFR5cGVzKCkge1xuXG5cdFx0cmV0dXJuIHtcblx0XHRcdGZvcm1faWQ6IFByb3BUeXBlcy5udW1iZXIsIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgY2FtZWxjYXNlXG5cdFx0XHRzaG93X3RpdGxlOiBQcm9wVHlwZXMuc3RyaW5nLCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNhbWVsY2FzZVxuXHRcdFx0c2hvd19kZXNjOiBQcm9wVHlwZXMuc3RyaW5nLCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNhbWVsY2FzZVxuXHRcdH07XG5cdH1cblxuXHQvKipcblx0ICogQ2hlY2sgaWYgZm9ybSBzZXR0aW5ncyB3YXMgdXBkYXRlZC5cblx0ICpcblx0ICogQHNpbmNlIDEuNi4zXG5cdCAqXG5cdCAqIEBwYXJhbSB7b2JqZWN0fSBwcmV2UHJvcHMgTGlzdCBvZiBwcmV2aW91cyBwcm9wZXJ0aWVzLlxuXHQgKi9cblx0Y29tcG9uZW50RGlkVXBkYXRlKCBwcmV2UHJvcHMgKSB7XG5cblx0XHRpZiAoIHByZXZQcm9wcy5mb3JtX2lkICE9PSB0aGlzLnByb3BzLmZvcm1faWQgfHwgcHJldlByb3BzLnNob3dfdGl0bGUgIT09IHRoaXMucHJvcHMuc2hvd190aXRsZSB8fCBwcmV2UHJvcHMuc2hvd19kZXNjICE9PSB0aGlzLnByb3BzLnNob3dfZGVzYyApIHtcblx0XHRcdHRoaXMuY29tcG9uZW50RGlkTW91bnQoKTtcblx0XHR9XG5cdH1cblxuXHQvKipcblx0ICogQWpheCByZXF1ZXN0IGZvciBmb3JtIEhUTUwuXG5cdCAqXG5cdCAqIEBzaW5jZSAxLjYuM1xuXHQgKi9cblx0Y29tcG9uZW50RGlkTW91bnQoKSB7XG5cblx0XHR2YXIgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTtcblxuXHRcdGZvcm1EYXRhLmFwcGVuZCggJ25vbmNlJywgd3Bmb3Jtc19kaXZpX2J1aWxkZXIubm9uY2UgKTtcblx0XHRmb3JtRGF0YS5hcHBlbmQoICdhY3Rpb24nLCAnd3Bmb3Jtc19kaXZpX3ByZXZpZXcnICk7XG5cdFx0Zm9ybURhdGEuYXBwZW5kKCAnZm9ybV9pZCcsIHRoaXMucHJvcHMuZm9ybV9pZCApO1xuXHRcdGZvcm1EYXRhLmFwcGVuZCggJ3Nob3dfdGl0bGUnLCB0aGlzLnByb3BzLnNob3dfdGl0bGUgKTtcblx0XHRmb3JtRGF0YS5hcHBlbmQoICdzaG93X2Rlc2MnLCB0aGlzLnByb3BzLnNob3dfZGVzYyApO1xuXG5cdFx0ZmV0Y2goXG5cdFx0XHR3cGZvcm1zX2RpdmlfYnVpbGRlci5hamF4X3VybCxcblx0XHRcdHtcblx0XHRcdFx0bWV0aG9kOiAnUE9TVCcsXG5cdFx0XHRcdGNhY2hlOiAnbm8tY2FjaGUnLFxuXHRcdFx0XHRjcmVkZW50aWFsczogJ3NhbWUtb3JpZ2luJyxcblx0XHRcdFx0aGVhZGVyczoge1xuXHRcdFx0XHRcdCdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcblx0XHRcdFx0XHQnQ2FjaGUtQ29udHJvbCc6ICduby1jYWNoZScsXG5cdFx0XHRcdH0sXG5cdFx0XHRcdGJvZHk6IG5ldyBVUkxTZWFyY2hQYXJhbXMoIGZvcm1EYXRhICksXG5cdFx0XHR9LFxuXHRcdClcblx0XHRcdC50aGVuKCByZXMgPT4gcmVzLmpzb24oKSApXG5cdFx0XHQudGhlbihcblx0XHRcdFx0KCByZXN1bHQgKSA9PiB7XG5cblx0XHRcdFx0XHR0aGlzLnNldFN0YXRlKCB7XG5cdFx0XHRcdFx0XHRpc0xvYWRpbmc6IGZhbHNlLFxuXHRcdFx0XHRcdFx0Zm9ybTogcmVzdWx0LmRhdGEsXG5cdFx0XHRcdFx0fSApO1xuXHRcdFx0XHR9LFxuXHRcdFx0XHQoIGVycm9yICkgPT4ge1xuXG5cdFx0XHRcdFx0dGhpcy5zZXRTdGF0ZSgge1xuXHRcdFx0XHRcdFx0aXNMb2FkaW5nOiBmYWxzZSxcblx0XHRcdFx0XHRcdGVycm9yLFxuXHRcdFx0XHRcdH0gKTtcblx0XHRcdFx0fSxcblx0XHRcdCk7XG5cdH1cblxuXHQvKipcblx0ICogUmVuZGVyIG1vZHVsZSB2aWV3LlxuXHQgKlxuXHQgKiBAc2luY2UgMS42LjNcblx0ICpcblx0ICogQHJldHVybnMge0pTWC5FbGVtZW50fSBWaWV3IGZvciBtb2R1bGUuXG5cdCAqL1xuXHRyZW5kZXIoKSB7XG5cblx0XHR2YXIgeyBlcnJvciwgaXNMb2FkZWQsIGZvcm0gfSA9IHRoaXMuc3RhdGUsXG5cdFx0XHR3cmFwcGVyQ2xhc3NlcyA9IGlzTG9hZGVkID8gJ3dwZm9ybXMtZGl2aS1mb3JtLXByZXZpZXcgbG9hZGluZycgOiAnd3Bmb3Jtcy1kaXZpLWZvcm0tcHJldmlldyc7XG5cblx0XHRpZiAoIGVycm9yIHx8ICEgZm9ybSApIHtcblxuXHRcdFx0cmV0dXJuIChcblx0XHRcdFx0PGRpdiBjbGFzc05hbWU9XCJ3cGZvcm1zLWRpdmktZm9ybS1wbGFjZWhvbGRlclwiPlxuXHRcdFx0XHRcdDxpbWcgc3JjPXt3cGZvcm1zX2RpdmlfYnVpbGRlci5wbGFjZWhvbGRlcn0vPlxuXHRcdFx0XHRcdDxoMz57d3Bmb3Jtc19kaXZpX2J1aWxkZXIucGxhY2Vob2xkZXJfdGl0bGV9PC9oMz5cblx0XHRcdFx0PC9kaXY+XG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdHJldHVybiAoXG5cdFx0XHQ8ZGl2IGNsYXNzTmFtZT17d3JhcHBlckNsYXNzZXN9PlxuXHRcdFx0XHR7PGRpdiBkYW5nZXJvdXNseVNldElubmVySFRNTD17eyBfX2h0bWw6IGZvcm0gfX0vPn1cblx0XHRcdDwvZGl2PlxuXHRcdCk7XG5cdH1cbn1cblxualF1ZXJ5KCB3aW5kb3cgKVxuXG5cdC8vIFJlZ2lzdGVyIGN1c3RvbSBtb2R1bGVzLlxuXHQub24oICdldF9idWlsZGVyX2FwaV9yZWFkeScsICggZXZlbnQsIEFQSSApID0+IHtcblx0XHRBUEkucmVnaXN0ZXJNb2R1bGVzKCBbIFdQRm9ybXNTZWxlY3RvciBdICk7XG5cdH0gKVxuXG5cdC8vIFJlLWluaXRpYWxpemUgV1BGb3JtcyBmcm9udGVuZC5cblx0Lm9uKCAnd3Bmb3Jtc0RpdmlNb2R1bGVEaXNwbGF5JywgKCBldmVudCApID0+IHtcblx0XHR3aW5kb3cud3Bmb3Jtcy5pbml0KCk7XG5cdH0gKTtcblxuLy8gTWFrZSBhbGwgdGhlIG1vZGVybiBkcm9wZG93bnMgZGlzYWJsZWQuXG5qUXVlcnkoIGRvY3VtZW50IClcblx0Lm9uKCAnd3Bmb3Jtc1JlYWR5JywgKCBldmVudCApID0+IHtcblxuXHRcdHZhciAkID0galF1ZXJ5O1xuXG5cdFx0JCggJy5jaG9pY2VzanMtc2VsZWN0JyApLmVhY2goIGZ1bmN0aW9uKCkge1xuXG5cdFx0XHR2YXIgJGluc3RhbmNlID0gJCggdGhpcyApLmRhdGEoICdjaG9pY2VzanMnICk7XG5cblx0XHRcdGlmICggISAkaW5zdGFuY2UgfHwgdHlwZW9mICRpbnN0YW5jZS5kaXNhYmxlICE9PSAnZnVuY3Rpb24nICkge1xuXHRcdFx0XHRyZXR1cm47XG5cdFx0XHR9XG5cblx0XHRcdCRpbnN0YW5jZS5kaXNhYmxlKCk7XG5cdFx0fSApO1xuXHR9ICk7XG4iXSwi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
},{"prop-types":6,"react":14}]},{},[15])