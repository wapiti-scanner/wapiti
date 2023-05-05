import './stat-block-style.scss';

/* eslint react/react-in-jsx-scope: 0 */
const StatBlock = props => {
	return (
		<div className="backup__card">
			<img src={ props.icon } alt="" />
			<div className="backup__card-details">
				<div className="backup__card-details-items">{ props.label }</div>
				<div className="backup__card-details-amount">{ props.value }</div>
			</div>
		</div>
	);
};

export default StatBlock;
