/* global eauthSpfApi */

jQuery(($) => {
	const checker = EmailAuthPlugin.instance.makeChecker(
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
				$('<div>').append(
					'Result code: ',
					$('<code>').text(res.code),
					' for server ',
					$('<code>').text(res.server_ip)
				),
				EmailAuthPlugin.createCommentList(
					res.code_reasons,
					'Details',
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
			get: () => ({
				alignment: EmailAuthPlugin.instance.bounceDomain,
				record: EmailAuthPlugin.instance.bounceDomain,
			}),
			type: 'Bounce Address',
			link: '#bounce-address',
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'bouncedomainchange',
		checker.boundCheck
	);
});
