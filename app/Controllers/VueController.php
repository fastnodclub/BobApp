<?php

namespace App\Controllers;

use App\Models\EmailVerify;
use App\Models\InviteCode;
use App\Models\LoginIp;
use App\Models\User;
use App\Models\Code;
use App\Models\Payback;
use App\Models\Ann;
use App\Models\Shop;
use App\Services\Auth;
use App\Services\Config;
use App\Services\MalioConfig;
use App\Utils\AntiXSS;
use App\Utils\Check;
use App\Utils\GA;
use App\Utils\Hash;
use App\Utils\Radius;
use App\Utils\Tools;
use App\Utils\TelegramSessionManager;
use App\Utils\Geetest;
use App\Utils\URL;
use App\Models\Node;
use App\Models\Relay;
use Psr\Http\Message\ResponseInterface;
use Ramsey\Uuid\Uuid;

class VueController extends BaseController
{
    /**
     * 注册接口
     *
     * @param $request
     * @param $response
     * @return mixed
     * @author  Bob<bob@bobcoder.cc>
     */
    public function register($request, $response)
    {
        if (Config::get('register_mode') === 'close') {
            $res['ret'] = 0;
            $res['msg'] = '未开放注册。';
            return $response->getBody()->write(json_encode($res));
        }
        $name = $request->getParam('name');
        $email = $request->getParam('email');
        $email = trim($email);
        $email = strtolower($email);
        $passwd = $request->getParam('passwd');
        $repasswd = $request->getParam('repasswd');
        $code = $request->getParam('code');
        $code = trim($code);
        $imtype = $request->getParam('imtype');
        $emailcode = $request->getParam('emailcode');
        $emailcode = trim($emailcode);
        $wechat = $request->getParam('wechat');
        $wechat = trim($wechat);
        // check code

        $sms_code = $request->getParam('sms_code');
        $sms_code = trim($sms_code);
        $phone = $request->getParam('phone');
        $phone = trim($phone);

        $area_code = $request->getParam('area_code');

        $full_phone = $area_code . $phone;

        //dumplin：1、邀请人等级为0则邀请码不可用；2、邀请人invite_num为可邀请次数，填负数则为无限
        $c = InviteCode::where('code', $code)->first();
        if ($c == null && MalioConfig::get('code_required') == true) {
            if (Config::get('register_mode') === 'invite') {
                $res['ret'] = 0;
                $res['msg'] = '邀请码无效';
                return $response->getBody()->write(json_encode($res));
            }
        } elseif ($c->user_id != 0) {
            $gift_user = User::where('id', '=', $c->user_id)->first();
            if ($gift_user == null) {
                $res['ret'] = 0;
                $res['msg'] = '邀请人不存在';
                return $response->getBody()->write(json_encode($res));
            }

            if ($gift_user->class == 0 && MalioConfig::get('code_required') == true) {
                $res['ret'] = 0;
                $res['msg'] = '邀请人不是VIP';
                return $response->getBody()->write(json_encode($res));
            }

            if ($gift_user->invite_num == 0 && MalioConfig::get('code_required') == true) {
                $res['ret'] = 0;
                $res['msg'] = '邀请人可用邀请次数为0';
                return $response->getBody()->write(json_encode($res));
            }
        }


        // check email format
        if (!Check::isEmailLegal($email)) {
            $res['ret'] = 0;
            $res['msg'] = '邮箱无效';
            return $response->getBody()->write(json_encode($res));
        }
        $email_postfix = '@' . (explode("@", $email)[1]);
        if (in_array($email_postfix, MalioConfig::get('register_email_black_list')) == true) {
            $res['ret'] = 0;
            $res['msg'] = '邮箱后缀已被拉黑';
            return $response->getBody()->write(json_encode($res));
        }
        if (MalioConfig::get('enable_register_email_restrict') == true) {
            if (in_array($email_postfix, MalioConfig::get('register_email_white_list')) == false) {
                $res['ret'] = 0;
                $res['msg'] = '小老弟还会发送post请求啊';
                return $response->getBody()->write(json_encode($res));
            }
        }
        // check email
        $user = User::where('email', $email)->first();
        if ($user != null) {
            $res['ret'] = 0;
            $res['msg'] = '邮箱已经被注册了';
            return $response->getBody()->write(json_encode($res));
        }

        // check pwd length
        if (strlen($passwd) < 8) {
            $res['ret'] = 0;
            $res['msg'] = '密码请大于8位';
            return $response->getBody()->write(json_encode($res));
        }

        // check pwd re
        if ($passwd != $repasswd) {
            $res['ret'] = 0;
            $res['msg'] = '两次密码输入不符';
            return $response->getBody()->write(json_encode($res));
        }
        // do reg user
        $user = new User();

        $antiXss = new AntiXSS();


        $user->user_name = $antiXss->xss_clean($name);
        $user->email = $email;
        $user->pass = Hash::passwordHash($passwd);
        $user->passwd = Tools::genRandomChar(6);
        $user->port = Tools::getAvPort();
        $user->t = 0;
        $user->u = 0;
        $user->d = 0;
        $user->method = Config::get('reg_method');
        $user->protocol = Config::get('reg_protocol');
        $user->protocol_param = Config::get('reg_protocol_param');
        $user->obfs = Config::get('reg_obfs');
        $user->obfs_param = Config::get('reg_obfs_param');
        $user->forbidden_ip = Config::get('reg_forbidden_ip');
        $user->forbidden_port = Config::get('reg_forbidden_port');
        $user->im_type = $imtype;
        $user->im_value = $antiXss->xss_clean($wechat);
        $user->transfer_enable = Tools::toGB(Config::get('defaultTraffic'));
        $user->invite_num = Config::get('inviteNum');
        $user->auto_reset_day = Config::get('reg_auto_reset_day');
        $user->auto_reset_bandwidth = Config::get('reg_auto_reset_bandwidth');
        $user->money = 0;
        if ($full_phone == '') {
            $user->phone = null;
        } else {
            $user->phone = $full_phone;
        }

        //dumplin：填写邀请人，写入邀请奖励
        $user->ref_by = 0;
        if (($c != null) && $c->user_id != 0) {
            $gift_user = User::where('id', '=', $c->user_id)->first();
            if ($gift_user->invite_num != 0) {
                $user->ref_by = $c->user_id;
                $user->money = Config::get('invite_get_money');
                $gift_user->transfer_enable += Config::get('invite_gift') * 1024 * 1024 * 1024;
                --$gift_user->invite_num;
                $gift_user->save();
            };
        }


        $user->class_expire = date('Y-m-d H:i:s', time() + Config::get('user_class_expire_default') * 3600);
        $user->class = Config::get('user_class_default');
        $user->node_connector = Config::get('user_conn');
        $user->node_speedlimit = Config::get('user_speedlimit');
        $user->expire_in = date('Y-m-d H:i:s', time() + Config::get('user_expire_in_default') * 86400);
        $user->reg_date = date('Y-m-d H:i:s');
        $user->reg_ip = $_SERVER['REMOTE_ADDR'];
        $user->plan = 'A';
        $user->theme = Config::get('theme');

        $groups = explode(',', Config::get('ramdom_group'));

        $user->node_group = $groups[array_rand($groups)];

        $ga = new GA();
        $secret = $ga->createSecret();

        $user->ga_token = $secret;
        $user->ga_enable = 0;


        /* malio 增加UUID */
        $user->uuid = Uuid::uuid3(Uuid::NAMESPACE_DNS, ($user->passwd) . Config::get('key') . $user->id)->toString();
        /* malio end */


        if ($user->save()) {
            $res['ret'] = 1;
            $res['msg'] = '注册成功！正在进入登录界面';
            Radius::Add($user, $user->passwd);

            return $response->getBody()->write(json_encode($res));
        }

        $res['ret'] = 0;
        $res['msg'] = '未知错误';

        return $response->getBody()->write(json_encode($res));
    }

    /**
     * @param $request
     * @param $response
     * @return mixed
     * @author Bob(bobcoder@qq.com)
     */
    public function login($request, $response)
    {
        $email = $request->getParam('email');
        $email = trim($email);
        $email = strtolower($email);
        $passwd = $request->getParam('passwd');
        $user = User::where('email', '=', $email)->first();
        $rememberMe = $request->getParam('remember_me');

        if ($user == null) {
            $rs['ret'] = 0;
            $rs['msg'] = '邮箱不存在';
            return $response->getBody()->write(json_encode($rs));
        }

        if (!Hash::checkPassword($user->pass, $passwd)) {
            $rs['ret'] = 0;
            $rs['msg'] = '邮箱或者密码错误';


            $loginIP = new LoginIp();
            $loginIP->ip = $_SERVER['REMOTE_ADDR'];
            $loginIP->userid = $user->id;
            $loginIP->datetime = time();
            $loginIP->type = 1;
            $loginIP->save();

            return $response->getBody()->write(json_encode($rs));
        }

        $time = 3600 * 24;
        if ($rememberMe) {
            $time = 3600 * 24 * (Config::get('rememberMeDuration') ?: 7);
        }

        Auth::login($user->id, $time);
        $rs['ret'] = 1;
        $rs['msg'] = '登录成功';

        $loginIP = new LoginIp();
        $loginIP->ip = $_SERVER['REMOTE_ADDR'];
        $loginIP->userid = $user->id;
        $loginIP->datetime = time();
        $loginIP->type = 0;
        $loginIP->save();

        return $response->getBody()->write(json_encode($rs));
    }

    public function getGlobalConfig($request, $response, $args)
    {
        $GtSdk = null;
        $recaptcha_sitekey = null;
        $user = $this->user;
        if (Config::get('captcha_provider') != '') {
            switch (Config::get('captcha_provider')) {
                case 'recaptcha':
                    $recaptcha_sitekey = Config::get('recaptcha_sitekey');
                    break;
                case 'geetest':
                    $uid = time() . random_int(1, 10000);
                    $GtSdk = Geetest::get($uid);
                    break;
            }
        }

        if (Config::get('enable_telegram') == true) {
            $login_text = TelegramSessionManager::add_login_session();
            $login = explode('|', $login_text);
            $login_token = $login[0];
            $login_number = $login[1];
        } else {
            $login_token = '';
            $login_number = '';
        }

        $res['globalConfig'] = array(
            'geetest_html' => $GtSdk,
            'login_token' => $login_token,
            'login_number' => $login_number,
            'telegram_bot' => Config::get('telegram_bot'),
            'enable_logincaptcha' => Config::get('enable_login_captcha'),
            'enable_regcaptcha' => Config::get('enable_reg_captcha'),
            'enable_checkin_captcha' => Config::get('enable_checkin_captcha'),
            'base_url' => Config::get('baseUrl'),
            'recaptcha_sitekey' => $recaptcha_sitekey,
            'captcha_provider' => Config::get('captcha_provider'),
            'jump_delay' => Config::get('jump_delay'),
            'register_mode' => Config::get('register_mode'),
            'enable_email_verify' => Config::get('enable_email_verify'),
            'appName' => Config::get('appName'),
            'dateY' => date('Y'),
            'isLogin' => $user->isLogin,
            'enable_telegram' => Config::get('enable_telegram'),
            'enable_mylivechat' => Config::get('enable_mylivechat'),
            'enable_flag' => Config::get('enable_flag'),
            'payment_type' => Config::get('payment_system'),
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function vuelogout($request, $response, $args)
    {
        Auth::logout();
        $res['ret'] = 1;
        return $response->getBody()->write(json_encode($res));
    }

    public function getUserInfo($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $pre_user = URL::cloneUser($user);
        $user->ssr_url_all = URL::getAllUrl($pre_user, 0, 0);
        $user->ssr_url_all_mu = URL::getAllUrl($pre_user, 1, 0);
        $user->ss_url_all = URL::getAllUrl($pre_user, 0, 2);
        $ssinfo = URL::getSSConnectInfo($pre_user);
        $user->ssd_url_all = URL::getAllSSDUrl($ssinfo);
        $user->isAbleToCheckin = $user->isAbleToCheckin();
        $ssr_sub_token = LinkController::GenerateSSRSubCode($this->user->id, 0);
        $GtSdk = null;
        $recaptcha_sitekey = null;
        if (Config::get('captcha_provider') != '') {
            switch (Config::get('captcha_provider')) {
                case 'recaptcha':
                    $recaptcha_sitekey = Config::get('recaptcha_sitekey');
                    break;
                case 'geetest':
                    $uid = time() . random_int(1, 10000);
                    $GtSdk = Geetest::get($uid);
                    break;
            }
        }
        $Ann = Ann::orderBy('date', 'desc')->first();
        $display_ios_class = Config::get('display_ios_class');
        $ios_account = Config::get('ios_account');
        $ios_password = Config::get('ios_password');
        $mergeSub = Config::get('mergeSub');
        $subUrl = Config::get('subUrl');
        $baseUrl = Config::get('baseUrl');
        $user['online_ip_count'] = $user->online_ip_count();

        $res['info'] = array(
            'user' => $user,
            'ssrSubToken' => $ssr_sub_token,
            'displayIosClass' => $display_ios_class,
            'iosAccount' => $ios_account,
            'iosPassword' => $ios_password,
            'mergeSub' => $mergeSub,
            'subUrl' => $subUrl,
            'baseUrl' => $baseUrl,
            'ann' => $Ann,
            'recaptchaSitekey' => $recaptcha_sitekey,
            'GtSdk' => $GtSdk,
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getUserInviteInfo($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $code = InviteCode::where('user_id', $user->id)->first();
        if ($code == null) {
            $user->addInviteCode();
            $code = InviteCode::where('user_id', $user->id)->first();
        }

        $pageNum = $request->getParam('current');

        $paybacks = Payback::where('ref_by', $user->id)->orderBy('id', 'desc')->paginate(15, ['*'], 'page', $pageNum);
        if (!$paybacks_sum = Payback::where('ref_by', $user->id)->sum('ref_get')) {
            $paybacks_sum = 0;
        }
        $paybacks->setPath('/#/user/panel');

        $res['inviteInfo'] = array(
            'code' => $code,
            'paybacks' => $paybacks,
            'paybacks_sum' => $paybacks_sum,
            'invite_num' => $user->invite_num,
            'invitePrice' => Config::get('invite_price'),
            'customPrice' => Config::get('custom_invite_price'),
            'invite_gift' => Config::get('invite_gift'),
            'invite_get_money' => Config::get('invite_get_money'),
            'code_payback' => Config::get('code_payback'),
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getUserShops($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $shops = Shop::where('status', 1)->orderBy('name')->get();

        $res['arr'] = array(
            'shops' => $shops,
        );
        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getAllResourse($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $res['resourse'] = array(
            'money' => $user->money,
            'class' => $user->class,
            'class_expire' => $user->class_expire,
            'expire_in' => $user->expire_in,
            'online_ip_count' => $user->online_ip_count(),
            'node_speedlimit' => $user->node_speedlimit,
            'node_connector' => $user->node_connector,
        );
        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getNewSubToken($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $user->clean_link();
        $ssr_sub_token = LinkController::GenerateSSRSubCode($this->user->id, 0);

        $res['arr'] = array(
            'ssr_sub_token' => $ssr_sub_token,
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getNewInviteCode($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $user->clear_inviteCodes();
        $code = InviteCode::where('user_id', $this->user->id)->first();
        if ($code == null) {
            $this->user->addInviteCode();
            $code = InviteCode::where('user_id', $this->user->id)->first();
        }

        $res['arr'] = array(
            'code' => $code,
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getTransfer($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $res['arr'] = array(
            'todayUsedTraffic' => $user->TodayusedTraffic(),
            'lastUsedTraffic' => $user->LastusedTraffic(),
            'unUsedTraffic' => $user->unusedTraffic(),
        );

        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getCaptcha($request, $response, $args)
    {
        $GtSdk = null;
        $recaptcha_sitekey = null;
        if (Config::get('captcha_provider') != '') {
            switch (Config::get('captcha_provider')) {
                case 'recaptcha':
                    $recaptcha_sitekey = Config::get('recaptcha_sitekey');
                    $res['recaptchaKey'] = $recaptcha_sitekey;
                    break;
                case 'geetest':
                    $uid = time() . random_int(1, 10000);
                    $GtSdk = Geetest::get($uid);
                    $res['GtSdk'] = $GtSdk;
                    break;
            }
        }

        $res['respon'] = 1;
        return $response->getBody()->write(json_encode($res));
    }

    public function getChargeLog($request, $response, $args)
    {
        $user = $this->user;

        if (!$user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $pageNum = $request->getParam('current');

        $codes = Code::where('type', '<>', '-2')->where('userid', '=', $user->id)->orderBy('id', 'desc')->paginate(15, ['*'], 'page', $pageNum);
        $codes->setPath('/#/user/code');

        $res['codes'] = $codes;
        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    public function getNodeList($request, $response, $args)
    {
        $user = Auth::getUser();

        if (!$this->user->isLogin) {
            $res['ret'] = -1;
            return $response->getBody()->write(json_encode($res));
        }

        $nodes = Node::where('type', 1)->orderBy('node_class')->orderBy('name')->get();
        $relay_rules = Relay::where('user_id', $this->user->id)->orwhere('user_id', 0)->orderBy('id', 'asc')->get();
        if (!Tools::is_protocol_relay($user)) {
            $relay_rules = array();
        }

        $array_nodes = array();
        $nodes_muport = array();

        foreach ($nodes as $node) {
            if ($node->node_group != $user->node_group && $node->node_group != 0) {
                continue;
            }
            if ($node->sort == 9) {
                $mu_user = User::where('port', '=', $node->server)->first();
                $mu_user->obfs_param = $this->user->getMuMd5();
                $nodes_muport[] = array('server' => $node, 'user' => $mu_user);
                continue;
            }
            $array_node = array();

            $array_node['id'] = $node->id;
            $array_node['class'] = $node->node_class;
            $array_node['name'] = $node->name;
            if ($this->user->class < $node->node_class) {
                $array_node['server'] = '***.***.***.***';
            } elseif ($node->sort == 13) {
                $server = Tools::ssv2Array($node->server);
                $array_node['server'] = $server['add'];
            } else {
                $array_node['server'] = $node->server;
            }

            $array_node['sort'] = $node->sort;
            $array_node['info'] = $node->info;
            $array_node['mu_only'] = $node->mu_only;
            $array_node['group'] = $node->node_group;

            $array_node['raw_node'] = $node;
            $regex = Config::get('flag_regex');
            $matches = array();
            preg_match($regex, $node->name, $matches);
            if (isset($matches[0])) {
                $array_node['flag'] = $matches[0] . '.png';
            } else {
                $array_node['flag'] = 'unknown.png';
            }

            $node_online = $node->isNodeOnline();
            if ($node_online === null) {
                $array_node['online'] = 0;
            } elseif ($node_online === true) {
                $array_node['online'] = 1;
            } elseif ($node_online === false) {
                $array_node['online'] = -1;
            }

            if (in_array($node->sort, array(0, 7, 8, 10, 11, 12, 13))) {
                $array_node['online_user'] = $node->getOnlineUserCount();
            } else {
                $array_node['online_user'] = -1;
            }

            $nodeLoad = $node->getNodeLoad();
            if (isset($nodeLoad[0]['load'])) {
                $array_node['latest_load'] = (explode(' ', $nodeLoad[0]['load']))[0] * 100;
            } else {
                $array_node['latest_load'] = -1;
            }

            $array_node['traffic_used'] = (int)Tools::flowToGB($node->node_bandwidth);
            $array_node['traffic_limit'] = (int)Tools::flowToGB($node->node_bandwidth_limit);
            if ($node->node_speedlimit == 0.0) {
                $array_node['bandwidth'] = 0;
            } elseif ($node->node_speedlimit >= 1024.00) {
                $array_node['bandwidth'] = round($node->node_speedlimit / 1024.00, 1) . 'Gbps';
            } else {
                $array_node['bandwidth'] = $node->node_speedlimit . 'Mbps';
            }

            $array_node['traffic_rate'] = $node->traffic_rate;
            $array_node['status'] = $node->status;

            $array_nodes[] = $array_node;
        }

        $res['nodeinfo'] = array(
            'nodes' => $array_nodes,
            'nodes_muport' => $nodes_muport,
            'relay_rules' => $relay_rules,
            'user' => $user,
            'tools' => new Tools(),
        );
        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }

    /**
     * @param Request   $requesr
     * @param Response  $response
     * @param array     $args
     */
    public function getNodeInfo($request, $response, $args): ResponseInterface
    {
        $user = $this->user;
        $id = $args['id'];
        $mu = $request->getQueryParam('ismu');
        $relay_rule_id = $request->getQueryParam('relay_rule');
        $node = Node::find($id);

        if ($node == null) {
            return $response->withJson([null]);
        }

        switch ($node->sort) {
            case 0:
                if ((($user->class >= $node->node_class
                        && ($user->node_group == $node->node_group || $node->node_group == 0)) || $user->is_admin)
                    && ($node->node_bandwidth_limit == 0 || $node->node_bandwidth < $node->node_bandwidth_limit)
                ) {
                    return $response->withJson([
                        'ret' => 1,
                        'nodeInfo' => [
                            'node' => $node,
                            'user' => $user,
                            'mu' => $mu,
                            'relay_rule_id' => $relay_rule_id,
                            'URL' => URL::class,
                        ],
                    ]);
                }
                break;
            case 1:
                if ($user->class >= $node->node_class
                    && ($user->node_group == $node->node_group || $node->node_group == 0)
                ) {
                    $email = $user->email;
                    $email = Radius::GetUserName($email);
                    $json_show = 'VPN 信息<br>地址：' . $node->server
                        . '<br>用户名：' . $email . '<br>密码：' . $this->user->passwd
                        . '<br>支持方式：' . $node->method . '<br>备注：' . $node->info;

                    return $response->write(
                        $this->view()->assign('json_show', $json_show)->fetch('user/nodeinfovpn.tpl')
                    );
                }
                break;
            case 2:
                if ($user->class >= $node->node_class
                    && ($user->node_group == $node->node_group || $node->node_group == 0)) {
                    $email = $user->email;
                    $email = Radius::GetUserName($email);
                    $json_show = 'SSH 信息<br>地址：' . $node->server
                        . '<br>用户名：' . $email . '<br>密码：' . $this->user->passwd
                        . '<br>支持方式：' . $node->method . '<br>备注：' . $node->info;

                    return $response->write(
                        $this->view()->assign('json_show', $json_show)->fetch('user/nodeinfossh.tpl')
                    );
                }
                break;
            case 5:
                if ($user->class >= $node->node_class
                    && ($user->node_group == $node->node_group || $node->node_group == 0)) {
                    $email = $user->email;
                    $email = Radius::GetUserName($email);

                    $json_show = 'Anyconnect 信息<br>地址：' . $node->server
                        . '<br>用户名：' . $email . '<br>密码：' . $this->user->passwd
                        . '<br>支持方式：' . $node->method . '<br>备注：' . $node->info;

                    return $response->write(
                        $this->view()->assign('json_show', $json_show)->fetch('user/nodeinfoanyconnect.tpl')
                    );
                }
                break;
            case 10:
                if ((($user->class >= $node->node_class
                        && ($user->node_group == $node->node_group || $node->node_group == 0)) || $user->is_admin)
                    && ($node->node_bandwidth_limit == 0 || $node->node_bandwidth < $node->node_bandwidth_limit)) {
                    return $response->withJson([
                        'ret' => 1,
                        'nodeInfo' => [
                            'node' => $node,
                            'user' => $user,
                            'mu' => $mu,
                            'relay_rule_id' => $relay_rule_id,
                            'URL' => URL::class,
                        ],
                    ]);
                }
                break;
            case 13:
                if ((($user->class >= $node->node_class
                        && ($user->node_group == $node->node_group || $node->node_group == 0)) || $user->is_admin)
                    && ($node->node_bandwidth_limit == 0 || $node->node_bandwidth < $node->node_bandwidth_limit)) {
                    return $response->withJson([
                        'ret' => 1,
                        'nodeInfo' => [
                            'node' => $node,
                            'user' => $user,
                            'mu' => $mu,
                            'relay_rule_id' => $relay_rule_id,
                            'URL' => URL::class,
                        ],
                    ]);
                }
                break;
        }

        // Default and judgement fail return
        return $response->withJson([
            'ret' => 0,
            'nodeInfo' => [
                'message' => ':)',
            ],
        ]);
    }

    public function doCheckIn($request, $response, $args)
    {
        if (strtotime($this->user->expire_in) < time()) {
            $res['ret'] = 0;
            $res['msg'] = '您的账户已过期，无法签到。';
            return $response->getBody()->write(json_encode($res));
        }

        $checkin = $this->user->checkin();
        if ($checkin['ok'] === false) {
            $res['ret'] = 0;
            $res['msg'] = $checkin['msg'];
            return $this->echoJson($response, $res);
        }
        if (MalioConfig::get('daily_bonus_mode') == 'malio') {
            $traffic = random_int(MalioConfig::get('daily_bonus_settings')[$this->user->class]['min'], MalioConfig::get('daily_bonus_settings')[$this->user->class]['max']);
        } else {
            $traffic = random_int(Config::get('checkinMin'), Config::get('checkinMax'));
        }
        $this->user->transfer_enable += Tools::toMB($traffic);
        $this->user->last_check_in_time = time();
        $this->user->save();
        $res['msg'] = $this->i18n->get('got-daily-bonus',[$traffic]);
        $res['ret'] = 1;

        return $response->getBody()->write(json_encode($res));
    }
}
