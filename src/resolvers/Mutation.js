const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto'); // for generating reset password token
const { promisify } = require('util'); //NODE: take callback based functions and turn them into promise based
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');

const Mutations = {
  async createItem(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!');
    }

    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // This is how to create a relationship between the Item and the User
          user: {
            connect: {
              // create a relationship in prisma
              id: ctx.request.userId
            }
          },
          ...args
        }
      },
      info
    );
    console.log(item);
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
    if (!ctx.request.user) throw new Error('You must be signed in!');
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title user {id} }`);
    // 2. check if they own it or have permissions
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ['ADMIN', 'ITEMDELETE'].includes(permission)
    );

    if (!ownsItem && !hasPermissions) {
      throw new Error(`You don't have permission to do that!`);
    }
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

    await transport.sendMail({
      from: 'bob@bob.com',
      to: user.email,
      subject: 'Your Password Reset Token',
      html: makeANiceEmail(
        `Reset token: \n\n <a href=${
          process.env.FRONTEND_URL
        }/reset?resetToken=${resetToken}>Click here to reset</a>`
      )
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
  },
  async updatePermissions(parent, args, ctx, info) {
    // Check if logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do this!');
    }
    // Query the current user
    const currentUser = await ctx.db.query.user(
      {
        where: {
          id: ctx.request.userId
        }
      },
      info
    );
    // Check if they have permissions to do this
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
    // Update the permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions // because `permissions` is its own enum, have to use set syntax
          }
        },
        where: { id: args.userId }
      },
      info
    );
  },
  async addToCart(parent, args, ctx, info) {
    // 1. Make sure the user is signed in
    const { userId } = ctx.request;
    if (!userId) throw new Error('You must be signed in');
    // 2. Query the user's current cart
    const [exisitingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    });
    // 3. Check if that item is already in their cart and increment by 1 if it is
    if (exisitingCartItem) {
      console.log('This item is already in their cart');
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: exisitingCartItem.id },
          data: { quantity: exisitingCartItem.quantity + 1 }
        },
        info
      );
    }
    // 4. If its not, create a new cartItem for that user
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId }
          },
          item: {
            connect: { id: args.id }
          }
        }
      },
      info
    );
  },

  async removeFromCart(parent, args, ctx, info) {
    // 1. Find the cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: {
          id: args.id
        }
      },
      `{ id, user { id }}`
    );
    // 1.5 Make sure we found an item
    if (!cartItem) throw new Error('No item found!');
    // 2. Make sure they own that cart item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error('Not allowed');
    }
    // 3. Delete that cart item
    return ctx.db.mutation.deleteCartItem(
      {
        where: { id: args.id }
      },
      info
    );
  },
  async createOrder(parent, args, ctx, info) {
    // 1. Query the current user and make sure they are signed in
    const { userId } = ctx.request;
    if (!userId)
      throw new Error('You must be signed in to complete this order.');
    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{
      id
      name
      email
      cart {
        id
        quantity
        item { title price id description image largeImage }
      }}`
    );
    // 2. recalculate the total for the price
    const amount = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    console.log(`Going to charge for a total of ${amount}`);
    // 3. Create the stripe charge (turn token into $$$)
    const charge = await stripe.charges.create({
      amount,
      currency: 'USD',
      source: args.token
    });
    // 4. Convert the CartItems to OrderItems
    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: { id: userId } } // relate to currently logged in user
      };
      delete orderItem.id; // we don't want the ID (this is handled by Prisma), so delete
      return orderItem;
    });

    // 5. create the Order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount, // coming back from Stripe
        charge: charge.id, // the actual transacted ID
        items: { create: orderItems }, // Prisma an order and pass it an array of other items
        user: { connect: { id: userId } } // connect the user
      }
    });
    // 6. Clean up - clear the users cart, delete cartItems
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds // delete it IF the ID is in the array of cartItems
      }
    });
    // 7. Return the Order to the client
    return order;
  }
};

module.exports = Mutations;
