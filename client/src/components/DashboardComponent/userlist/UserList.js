import React, { Component } from 'react';
import {
  Table,
  TableBody,
  TableHeader,
  TableHeaderColumn,
  TableRow,
  TableRowColumn,
} from 'material-ui/Table';
import RaisedButton from 'material-ui/RaisedButton';
import axios from 'axios';

import './UserList.style.css';
import env from '../../../../config/env';

const submitButtonStyle = { backgroundColor: "#67c26f" };
const approveButtonStyle = { backgroundColor: "#84b043", marginRight: "15px" };
const blockButtonStyle = { backgroundColor: "#8c8f91", marginRight: "15px" };
const deleteButtonStyle = { backgroundColor: "#c25035", marginLeft: "15px" };

export default class UserTableComponent extends Component {

  constructor(props) {
    super(props);
    this.state = {
      render: false, //Set render state to false
      userData : []
    }
  }

  componentDidMount() {
    this.getUserList();
  }

  state = {
    fixedHeader: false,
    fixedFooter: false,
    stripedRows: false,
    showRowHover: false,
    selectable: false,
    height: '500px',
    token: localStorage.getItem("token")
  };

  getUserList() {
    axios.get(env.API_URL + '/auth/userlist', { headers: { token: this.state.token } })
      .then( (res) => {
        this.setState({ userData: res.data.users ? res.data.users : [], render: true });
      });
  }

  approveUser(email, flag) {
    axios.post(env.API_URL + '/auth/approve', { email, flag }, { headers: { token: this.state.token } })
      .then( (res) => {
        if (res.data.success) {
          let { userData } = this.state;
          userData.map((user, index) => {
            if (user.email === email) {
              console.log('match ', email);
              user.blocked = flag;
            }
            return user;
          });
          console.log(userData);
          this.setState({ userData: JSON.parse(JSON.stringify(userData)) });
        }
      });
  }

  deleteUser(email) {
    if (confirm("Do you want to remove user account " + email)) {
      axios.post(env.API_URL + '/auth/remove', { email }, { headers: { token: this.state.token } })
        .then( (res) => {
          if (res.data.success) {
            let { userData } = this.state;
            userData = userData.filter((user) => {
              return user.email !== email;
            });
            this.setState({ userData: JSON.parse(JSON.stringify(userData)) });
          }
        });
    }
  }

  render() {
    return (
      <div id="container">
        <RaisedButton label="Refresh" type="button" buttonStyle={submitButtonStyle}
                      onClick={() => this.getUserList()} />

        <div style={{width: '100%', height:"1400px"}}>
          <Table style={{width: '75%',textAlign: 'center', margin: 'auto'}}
            height={this.state.height}
            fixedHeader={this.state.fixedHeader}
            fixedFooter={this.state.fixedFooter}
            selectable={false}
          >
            <TableHeader
              style={{textAlign: 'center'}}
              displaySelectAll={false}
              adjustForCheckbox={false}
            >
              <TableRow style={{textAlign: 'center'}}>
                <TableHeaderColumn style={{color:"#FF1744", fontSize:"32"}} tooltip="The Email of User">Email</TableHeaderColumn>
                <TableHeaderColumn style={{color:"#FF1744" , fontSize:"32"}} tooltip="Created Date">Created Date</TableHeaderColumn>
                <TableHeaderColumn style={{color:"#FF1744" , fontSize:"32"}} tooltip="Last Pay Date">Last Pay Date</TableHeaderColumn>
                <TableHeaderColumn style={{color:"#FF1744", fontSize:"32"}} tooltip="Operation">Operation</TableHeaderColumn>
              </TableRow>
            </TableHeader>
            <TableBody displayRowCheckbox={false} style={{textAlign: 'center'}}
              showRowHover={this.state.showRowHover} >
              {
                this.state.userData.map(( user, index ) =>
                  <TableRow key={index}>
                    <TableRowColumn>{user.email}</TableRowColumn>
                    <TableRowColumn>{String(user.createdAt).substring(0, 10)}</TableRowColumn>
                    <TableRowColumn>{String(user.lastPayAt).substring(0, 10)}</TableRowColumn>
                    <TableRowColumn>
                      <RaisedButton label={user.blocked ? "approve" : "block"} type="button" buttonStyle={ user.blocked ? approveButtonStyle : blockButtonStyle }
                                    onClick={() => this.approveUser(user.email, !user.blocked)} />
                      <RaisedButton label="delete" type="button" buttonStyle={deleteButtonStyle}
                                    onClick={() => this.deleteUser(user.email)} />
                    </TableRowColumn>
                  </TableRow>
                )}
            </TableBody>
          </Table>
        </div>
      </div>
    );
  }
}
