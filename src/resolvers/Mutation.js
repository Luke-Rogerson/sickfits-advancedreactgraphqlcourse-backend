const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto'); // for generating reset password token
const { promisify } = require('util'); //NODE: take callback based functions and turn them into promise based

const Mutations = {
  async createItem(parent, args, ctx, info) {
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          ...args
        }
      },
      info
    );
    return item;
  },
  updateItem(parent, args, ctx, info) {
    // make a copy of the updates
    const updates = { ...args };
    // remove ID from the updates
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title }`);
    // 2. check if they own it or have permissions
    // TODO
    // 3. Delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signUp(parent, args, ctx, info) {
    args.email = args.email.toLowerCase(); //always lowercase emails!
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        // ctx to access our db
        data: {
          ...args, // this will give us name: args.name, email: args.password, etc
          password,
          permissions: { set: ['USER'] } //permissions isn't just string field, but reaching out to external enum
        }
      },
      info
    ); //pass info as 2nd argument so it knows what data to return to client
    // create the JWT token for them. This means they don't have to sign in again when they've just signed up
    const token = jwt.sign({ userID: user.id }, process.env.APP_SECRET);
    // Set the JWT as a cookie on the response as they are now signed in
    ctx.response.cookie('token', token, {
      httpOnly: true, // prevent client Javascript from modifying cookie
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // Finally, return user to the browser
    return user;
  },
  async signIn(parent, { email, password }, ctx, info) {
    // 1. check if there is a user with that email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No user found for email ${email}`);
    }
    // 2. check if their password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error('Incorrect password');
    }
    // 3. generate the JWT token
    const token = jwt.sign({ userID: user.id }, process.env.APP_SECRET);
    // 4. set the cookie with the token
    ctx.response.cookie('token', token),
      {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365
      };
    // 5. return the user
    return user;
  },
  signOut(parent, args, ctx, info) {
    ctx.response.clearCookie('token'); // Cookie parser in index gives us access to these functions
    return { message: 'Goodbye!' };
  },
  async requestReset(parent, args, ctx, info) {
    // Check if its a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if (!user) {
      throw new Error(`No user found for email ${args.email}`);
    }
    // Set a reset token and expiry on that user
    const randomBytesPromisified = promisify(randomBytes);
    const resetToken = (await randomBytesPromisified(20)).toString('hex'); // promisify callback function
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry } //data we want to update on that user
    });
    return { message: 'Thanks!' };

    // Email them that reset token
  },
  async resetPassword(
    parent,
    { resetToken, password, confirmPassword },
    ctx,
    info
  ) {
    if (password !== confirmPassword)
      throw new Error(`Your passwords don't match!`);

    const [user] = await ctx.db.query.users({
      where: { resetToken, resetTokenExpiry_gte: Date.now() - 3600000 }
    });

    if (!user) throw new Error(`This token is either invalid or expired!`);

    const newPassword = await bcrypt.hash(password, 10);

    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: { password: newPassword, resetToken: null, resetTokenExpiry: null }
    });

    const token = jwt.sign({ userID: updatedUser.id }, process.env.APP_SECRET);

    ctx.response.cookie('token', token),
      {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365
      };
    return updatedUser;
  }
};

module.exports = Mutations;
