/* global eauthSpfApi */

jQuery(($) => {
	const check = EmailAuthPlugin.instance.makeChecker(
		'spf',
		'SPF',
		() => `${eauthSpfApi.check}/${EmailAuthPlugin.instance.bounceDomain}`,
		() => {
			if (EmailAuthPlugin.instance.bounceDomain === null) {
				return {
					pass: null,
					reason: 'Unknown bounce address domain.',
				};
			}
		},
		(res) => {
			const out = [
				EmailAuthPlugin.createCheckedDomain(
					EmailAuthPlugin.instance.bounceDomain,
					'#bounce-address',
					'Bounce Address'
				),
				$('<h3>').text('Test Result'),
				$('<div>').append('Code: ', $('<code>').text(res.code)),
				EmailAuthPlugin.createCommentList(
					res.code_reasons,
					'Problems',
					'h4'
				),
			];

			out.push($('<h3>').text('Validity Check'));

			if (res.cur_rec) {
				out.push(
					$('<div>').append(
						'Current record: ',
						$('<code>').text(res.cur_rec)
					)
				);

				if (!res.cur_validity.length) {
					res.cur_validity.push({
						level: 'pass',
						desc: 'Current record is schematically valid.',
					});
				}

				out.push(
					EmailAuthPlugin.createCommentList(
						res.cur_validity,
						'Issues',
						'h4'
					)
				);
			} else {
				out.push(
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.error} No syntactically valid record found.`
					)
				);
			}

			if (res.rec_dns) {
				out.push($('<h3>').text('Suggested DNS Record'));

				out.push(
					EmailAuthPlugin.createTxtRecord(
						EmailAuthPlugin.instance.bounceDomain,
						res.rec_dns
					),
					EmailAuthPlugin.createCommentList(
						res.rec_reasons,
						'Reasons',
						'h4'
					)
				);
			}

			return out;
		},
		{
			alignment: {
				getDomain: () => EmailAuthPlugin.instance.bounceDomain,
				type: 'Bounce',
			},
		}
	);

	check();
	EmailAuthPlugin.instance.addEventListener('bouncedomainchange', check);
});
