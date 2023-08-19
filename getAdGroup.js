const ActiveDirectory = require("activedirectory2");
const { StatusCodes: HttpStatus } = require("http-status-codes")

async function getAdGroup(req,res,next){
    try {
        const domainName = "Your Domain URL"
        const domainUser = "Domain Admin Username"
        const domainPass = "Domain Admin Password"
        baseDN = domainName.split(".");
        const ad = new ActiveDirectory({
            url: `ldap://${domainName}`,
            baseDN: `dc=${baseDN[0]},dc=${baseDN[1]}`,
            username: `${domainUser}@${domainName}`,
            password: domainPass,
        })
        ad.findGroups((err, groups) => {
            if (err) {
                console.log(err);
                res.status(HttpStatus.BAD_GATEWAY).json({
                    StatusCode: HttpStatus.BAD_GATEWAY,
                    errors: {
                        message: err
                    }
                });
            }
            const allGroupWithUsers = [];
            let processedGroups = 0
            groups.forEach((group) => {
                ad.getUsersForGroup(group.cn, (err, users) => {
                    if (err) {
                        res.status(HttpStatus.BAD_GATEWAY).json({
                            StatusCode: HttpStatus.BAD_GATEWAY,
                            errors: {
                                message: err
                            }
                        });
                    }
                    const groupData = {
                        GroupName: group.cn,
                        members: users.map(user => ({
                            username: user.sAMAccountName,
                            firstname: user.givenName??undefined,
                            lastname: user.sn??undefined,
                            email: user.mail??undefined,
                            displayname: user.displayName??undefined,
                            description: user.description??undefined
                        }))
                    }
                    const groupCondition = groupData.members.length > 0
                        && groupData.members != 'Administrator'
                        && groupData.GroupName != 'Denied RODC Password Replication Group'
                        && groupData.GroupName != 'Administrators'
                        && groupData.GroupName != 'Guests'
                        && groupData.GroupName != 'Users'
                        && groupData.GroupName != 'Schema Admins'
                        && groupData.GroupName != 'Enterprise Admins'
                        && groupData.GroupName != 'Group Policy Creator Owners'
                    if (groupCondition) {
                        allGroupWithUsers.push(groupData)
                    }
                    processedGroups++
                    if (processedGroups === groups.length) {
                        res.status(HttpStatus.OK).json({
                            StatusCode: HttpStatus.OK,
                            data: {
                                allGroupWithUsers
                            }
                        });
                    }
                });
            })
        });
    } catch (error) {
        next(error)
    }
}
module.exports = {
    getAdGroup
}
