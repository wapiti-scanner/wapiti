import { Gridicon } from '@automattic/jetpack-components';
import classnames from 'classnames';
import noop from 'lodash/noop';
import PropTypes from 'prop-types';
import React from 'react';
/*eslint lodash/import-scope: [2, "method"]*/

import './style.scss';

export default class SimpleNotice extends React.Component {
	static displayName = 'SimpleNotice';

	static defaultProps = {
		duration: 0,
		status: null,
		showDismiss: true,
		className: '',
		onDismissClick: noop,
	};

	static propTypes = {
		// we should validate the allowed statuses
		status: PropTypes.string,
		showDismiss: PropTypes.bool,
		isCompact: PropTypes.bool,
		duration: PropTypes.number,
		text: PropTypes.oneOfType( [
			PropTypes.oneOfType( [ PropTypes.string, PropTypes.node ] ),
			PropTypes.arrayOf( PropTypes.oneOfType( [ PropTypes.string, PropTypes.node ] ) ),
		] ),
		icon: PropTypes.string,
		onDismissClick: PropTypes.func,
		className: PropTypes.string,
	};

	dismissTimeout = null;

	componentDidMount() {
		if ( this.props.duration > 0 ) {
			this.dismissTimeout = setTimeout( this.props.onDismissClick, this.props.duration );
		}
	}

	componentWillUnmount() {
		if ( this.dismissTimeout ) {
			clearTimeout( this.dismissTimeout );
		}
	}

	getIcon = () => {
		let icon;

		switch ( this.props.status ) {
			case 'is-info':
				icon = 'info';
				break;
			case 'is-success':
				icon = 'checkmark';
				break;
			case 'is-error':
				icon = 'notice';
				break;
			case 'is-warning':
				icon = 'notice';
				break;
			default:
				icon = 'info';
				break;
		}

		return icon;
	};

	clearText = text => {
		if ( 'string' === typeof text ) {
			return text.replace( /(<([^>]+)>)/gi, '' );
		}
		return text;
	};

	onKeyDownCallback = callback => event => {
		if ( event.which === 13 || event.which === 32 ) {
			callback && callback( event );
		}
	};

	render() {
		const {
			children,
			className,
			icon,
			isCompact,
			onDismissClick,
			showDismiss = ! isCompact, // by default, show on normal notices, don't show on compact ones
			status,
			text,
			dismissText,
		} = this.props;
		const classes = classnames( 'dops-notice', status, className, {
			'is-compact': isCompact,
			'is-dismissable': showDismiss,
		} );

		return (
			<div className={ classes }>
				<span className="dops-notice__icon-wrapper">
					<Gridicon className="dops-notice__icon" icon={ icon || this.getIcon() } size={ 24 } />
				</span>
				<span className="dops-notice__content">
					<span className="dops-notice__text">{ text ? this.clearText( text ) : children }</span>
				</span>
				{ text ? children : null }
				{ showDismiss && (
					<span
						role="button"
						onKeyDown={ this.onKeyDownCallback( onDismissClick ) }
						tabIndex="0"
						className="dops-notice__dismiss"
						onClick={ onDismissClick }
					>
						<Gridicon icon="cross" size={ 24 } />
						<span className="dops-notice__screen-reader-text screen-reader-text">
							{ dismissText }
						</span>
					</span>
				) }
			</div>
		);
	}
}
