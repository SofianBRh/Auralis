<template>
    <div>
      <h3>Tableau de bord</h3>
      <div>
        <h4>Requêtes envoyées :</h4>
        <ul>
          <li v-for="(request, index) in requests" :key="index">{{ request }}</li>
        </ul>
      </div>
      <div>
        <h4>Réponses :</h4>
        <ul>
          <li v-for="(response, index) in responses" :key="index">{{ response }}</li>
        </ul>
      </div>
    </div>
  </template>
  
  <script>
  export default {
    data() {
      return {
        requests: [],
        responses: []
      };
    },
    methods: {
      addRequest(request) {
        this.requests.push(request);
      },
      addResponse(response) {
        this.responses.push(response);
      }
    },
    created() {
      this.$root.$on("request-sent", this.addRequest);
      this.$root.$on("response-received", this.addResponse);
    },
    beforeDestroy() {
      this.$root.$off("request-sent", this.addRequest);
      this.$root.$off("response-received", this.addResponse);
    }
  }
  </script>  