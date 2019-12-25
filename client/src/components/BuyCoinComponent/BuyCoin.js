import React, { Component } from 'react';

import { withRouter } from 'react-router-dom';
import env from '../../../config/env';
import './BuyCoin.css';

class BuyCoin extends Component {
  constructor(props){
    super(props);

    this.alertOptions = {
      offset: 100,
      position: 'top',
      theme: 'dark',
      timeout: 5000,
      transition: 'scale',
      html: true
    };

    this.state = {
      showAlert: false,
      role: localStorage.getItem(("role"))
    }
  }

  gotoLogin() {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    setTimeout(this.props.history.push("/"), 2000);
  }

  render() {
    return (
      <div className='login'>
        <h1 id='loginHeader'>Buy WTC Coin</h1>
        <h3> 220 WTC Coin </h3>
        <h3> License for 7 days </h3>
        <h3> Wallet Id </h3>
        <h3> { env.WALLET_ID } </h3>
        <h3> Send Tx code and email to </h3>
        <h3> { env.CONTACT_EMAIL } </h3>
        <a target='_blank' href={ env.PURCHASE_URL }>
          <input id='login' type='button' defaultValue='Buy Now' ref='buycoin' />
        </a>
        <hr />
        <input id='login' type='button' defaultValue='Sign in' ref='signin' onClick={ () => this.gotoLogin() } />
      </div>
    );
  }
}

export default withRouter(BuyCoin);

