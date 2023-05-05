/* eslint-disable jsx-a11y/click-events-have-key-events */
/* eslint-disable jsx-a11y/no-static-element-interactions */

import classNames from 'classnames';
import PropTypes from 'prop-types';
import React, { Component, Fragment } from 'react';

import './style.scss';

export default class FormToggle extends Component {
	static propTypes = {
		onChange: PropTypes.func,
		onKeyDown: PropTypes.func,
		checked: PropTypes.bool,
		disabled: PropTypes.bool,
		id: PropTypes.string,
		className: PropTypes.string,
		toggling: PropTypes.bool,
		'aria-label': PropTypes.string,
		children: PropTypes.node,
		disabledReason: PropTypes.node,
		switchClassNames: PropTypes.string,
		labelClassNames: PropTypes.string,
	};

	static defaultProps = {
		checked: false,
		disabled: false,
		onKeyDown: () => {},
		onChange: () => {},
		disabledReason: '',
	};

	state = {};

	static idNum = 0;

	constructor() {
		super( ...arguments );

		this.onKeyDown = this.onKeyDown.bind( this );
		this.onClick = this.onClick.bind( this );
		this.onLabelClick = this.onLabelClick.bind( this );
	}

	UNSAFE_componentWillMount() {
		this.id = this.constructor.idNum++;
	}

	onKeyDown( event ) {
		if ( this.props.disabled ) {
			return;
		}

		if ( event.key === 'Enter' || event.key === ' ' ) {
			event.preventDefault();
			this.props.onChange();
		}

		this.props.onKeyDown( event );
	}

	onClick() {
		if ( ! this.props.disabled ) {
			this.props.onChange();
		}
	}

	onLabelClick( event ) {
		if ( this.props.disabled ) {
			return;
		}

		const nodeName = event.target.nodeName.toLowerCase();
		if ( nodeName !== 'a' && nodeName !== 'input' && nodeName !== 'select' ) {
			event.preventDefault();
			this.props.onChange();
		}
	}

	render() {
		const id = this.props.id || 'toggle-' + this.id;
		const toggleClasses = classNames( 'form-toggle', this.props.className, {
			'is-toggling': this.props.toggling,
		} );

		return (
			<Fragment>
				<div
					className={ classNames( 'form-toggle__switch-container', this.props.switchClassNames ) }
				>
					<input
						className={ toggleClasses }
						type="checkbox"
						checked={ this.props.checked }
						readOnly={ true }
						disabled={ this.props.disabled }
					/>
					<span
						className={ classNames( 'form-toggle__switch', this.props.switchClassNames ) }
						disabled={ this.props.disabled }
						id={ id }
						onClick={ this.onClick }
						onKeyDown={ this.onKeyDown }
						role="checkbox"
						aria-checked={ this.props.checked }
						aria-label={ this.props[ 'aria-label' ] }
						tabIndex={ this.props.disabled ? -1 : 0 }
						ref="toggleSwitch"
					/>
				</div>
				<label
					className={ classNames( 'form-toggle__label', this.props.labelClassNames ) }
					htmlFor={ id }
				>
					<span
						className={ classNames( 'form-toggle__label-content', this.props.labelClassNames ) }
						onClick={ this.onLabelClick }
					>
						{ this.props.children }
					</span>
				</label>
			</Fragment>
		);
	}
}
