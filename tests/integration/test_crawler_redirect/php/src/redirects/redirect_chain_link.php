<?php
if(isset($_GET['redirect_left']) && intval($_GET['redirect_left'])>0){
    header("location: /redirects/redirect_chain_link.php?redirect_left=" . intval($_GET['redirect_left'])-1);

}else{
    header("location: /redirect_target.php?origin=redirect_chain_link");
}
header("x-xss-protection: 1; mode=block");
header("x-content-type-options: nosniff");
header("x-frame-options: SAMEORIGIN");
header("vary: Accept-Encoding");
?>
